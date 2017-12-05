(* Copyright (C) 2015, Thomas Leonard <thomas.leonard@unikernel.com>
   See the README file for details. *)

(** {2 Actions}

  The possible actions are:

    - [`Accept] : Send the packet to its destination.

    - [`NAT] : Rewrite the packet's source field so packet appears to
      have come from the firewall, via an unused port.
      Also, add NAT rules so related packets will be translated accordingly.

    - [`NAT_to (host, port)] :
      As for [`NAT], but also rewrite the packet's destination fields so it
      will be sent to [host:port].

    - [`Drop reason] drop the packet and log the reason.
*)

open Packet (* make mirage configure -t xen realize that we need Packet*)
open Mirage

type item = Packet.info
type unres = Unresolved

type _ action =
  (* Resolved: *)
  | Accept : ipv4 action
  | NAT    : ipv4 action
  | NAT_to : { host : Packet.host ;
               port : Packet.port ;
              } -> Mirage.ipv4 action
  | Drop : { reason : string option; } -> Mirage.ipv4 action
  (* Unresolved actions: *)
  | Match_dst : (item -> rule) -> unres action
  | Match_src : (item -> rule) -> unres action
  | Match_proto : (item -> rule) -> unres action
and rule =
  | Action of unres action (* "Stop matcing and resolve action" *)
  | Resolution of Mirage.ipv4 action option

let rec match_rule (packet:Packet.info) rule : Mirage.ipv4 action option =
  let match_unres (unres : unres action) =
    match unres with (*TODO why the fuck does merlin warn about unmatched stuff?*)
    ( Match_dst (f:item -> rule)
    | Match_src f
    | Match_proto f
    ) ->f
  in
  begin match rule with
    | Resolution solv -> solv
    | Action unres -> match_rule packet ((match_unres unres) packet)
  end

(*
type condition =
  {
    src : Packet.host option ;
    src_cidr : Ipaddr.Prefix.t option ;
    dst : Packet.host option ;
    dst_cdir : Ipaddr.Prefix.t option ;
    proto : Packet.proto option ;
    sport_range : (int * int) option ;
    dport_range : (int * int) option ;
  }
*)

type port_range = (int * int) option
type proto_match = Match_UDP of (port_range * port_range)
                 | Match_TCP of (port_range * port_range)
                 | Match_ICMP
                 | Match_Unknown

type addr_match = | Match_addr_wildcard
                  | External_V4_CIDR of Ipaddr.V4.Prefix.t (* `External (V4 _)*)
                  | External_V6_CIDR of Ipaddr.V6.Prefix.t (* `External (V6 _)*)
                  | Client_V4_CIDR of Ipaddr.V4.Prefix.t (* for `Client _ *)
                  | Magic of [`NetVM | `Client_gateway | `Firewall_uplink]

type condition = Proto_match of proto_match | Addr_match of addr_match

type ruleset =
  { default_action : ipv4 action ;
    rules: rule list;
  } (* a ruleset dealing with traffic in one direction *)

let src = Logs.Src.create "firewall" ~doc:"Rules handler"
module Log = (val Logs.src_log src : Logs.LOG)

let make_condition_match_all (lst : 'a list) (action : Mirage.ipv4 action)
  : rule =
  let rec loop (acc : rule) lst =
    let match_addr (host:Packet.host) addr_match =
      match host, addr_match with
      | _, Match_addr_wildcard -> true
      | `External (Ipaddr.V4 addr), External_V4_CIDR cidr ->
        Ipaddr.V4.Prefix.mem addr cidr
      | `External (Ipaddr.V6 addr), External_V6_CIDR cidr ->
        Ipaddr.V6.Prefix.mem addr cidr
      | `Client client, Client_V4_CIDR cidr ->
        (* why the fuck is this an object??? *)
        Ipaddr.V4.Prefix.mem (client#other_ip) cidr
      | (`NetVM | `Client_gateway | `Firewall_uplink) as a, Magic b -> a = b
      (* illegal combinations, the price for not knowing the direction: *)
      | (`NetVM | `Client_gateway | `Firewall_uplink), ( External_V4_CIDR _
                                                       | External_V6_CIDR _
                                                       | Client_V4_CIDR _
                                                       ) ->
        (* big elephant in the room: we can't match CIDR ranges on these magic
           things, TODO look for a function somewhere in here to resolve them:*)
        false
      | (`External _ | `Client _), Magic _
      | `External _ , Client_V4_CIDR _
      | `External (Ipaddr.V4 _), External_V6_CIDR _ (* TODO this might be ok? *)
      | `Client _ , (External_V4_CIDR _ | External_V6_CIDR _) -> false
      (* special place in hell reserved for IPv6: *)
      | Ipaddr.(`External (V6 _)), External_V4_CIDR _ -> false
    in
    let or_default tl b = if b then loop acc tl else Resolution None in
    begin match lst with
      | [] -> acc
      | (`Dst m)::tl -> (* Check that destination matches *)
        Action (Match_dst (fun a ->
            Logs.app (fun f -> f "TODO checking that destination is good: %b"
                         (match_addr a.dst m)
                     );
            or_default tl (match_addr a.dst m)))
      | (`Src m)::tl -> (* Check that source matches *)
        Action (Match_src (fun a ->
            Logs.app (fun f -> f "TODO checking that SOURCE is good: %b"
                         (match_addr a.src m)
                     );
            or_default tl (match_addr a.src m)))
      | (`Proto m)::tl ->
        let in_range port range = match range with
          | None -> true (* <-- no range filter was given *)
          | Some (low,high) -> low <= port && port <= high
        in
        Action (Match_proto
                  (fun a ->
                     or_default tl
                      (match m, a.proto with
                       | Match_ICMP, `ICMP
                       | Match_Unknown, `Unknown -> true
                       | ( Match_UDP (None,None), `UDP _ (* fast track: *)
                         | Match_TCP (None,None), `TCP _) -> true
                       | ( Match_UDP (src_r, dst_r), `UDP {sport; dport}
                         | Match_TCP (src_r, dst_r), `TCP {sport; dport}) ->
             (*check ranges: *) (in_range sport src_r) && (in_range dport dst_r)
                       | _ -> false)))

    end
  in loop (Resolution (Some action)) lst

let drop reason : ipv4 action = Drop {reason}
let nat_to host (port:int) : ipv4 action = NAT_to {host;port}

let apply_rules (type input) (type return)
    {default_action ; rules}
    (packet)
  : Mirage.ipv4 action =
  let rec check_rules = function
    | hd::tl ->
      begin match match_rule packet hd with
        | None -> check_rules tl
        | Some res -> res
      end
    | [] -> default_action
  in check_rules rules

open Yojson
(*
== conditions:

- {"proto": {"udp": {"sport_range": [], "dport_range": [53,53]} } }
- {"proto": {"tcp": {"sport_range": [], "dport_range": [53,53]} } }
- {"proto": {"icmp": ""} }
- {"proto": {"unknown": ""} }/* TODO match IP protonum */

- {"dst": "*"} /* Match_addr_wildcard */
- {"src": {"external_cidr": "8.8.8.8/32"}} /* External_V4_CIDR */
- {"dst": {"client_cidr": "8.8.8.8/32"}} /* Client_V4_CIDR */
- {"src": "netvm"}
- {"dst": "client_gateway"}
- {"src": "firewall_uplink"}

== schema
{ "ingress": [
    {"accept": [cond_1, cond_2]},
    {"nat": [cond_a, cond_b, cond_c]},
    {"drop": [cond_x, cond_y],
     "reason": "because I do not like this host",
    },
    {"nat_to": [cond_q, cond_w, cond_e],
     "host": "1.2.3.4",
     "port": "8080",
    },
  ],
  "egress": [
  ]
}
*)

let parse_addr : Yojson.Basic.json -> addr_match = function
  | `Assoc ["external_cidr", `String cidr ] ->
    begin match Ipaddr.V4.Prefix.of_string cidr with
      | None -> failwith "invalid cidr in firewall rules"
      | Some x -> External_V4_CIDR x end
  | `Assoc ["client_cidr", `String cidr ] ->
        begin match Ipaddr.V4.Prefix.of_string cidr with
      | None -> failwith "invalid cidr in firewall rules"
      | Some x -> Client_V4_CIDR x end
  | `String "*" -> Match_addr_wildcard
  | `String "netvm" -> Magic `NetVM
  | `String "client_gateway" -> Magic `Client_gateway
  | `String "firewall_uplink" -> Magic `Firewall_uplink
  | _ -> failwith "json firewall config parsing addr - and failed"

let parse_ports : Yojson.Basic.json -> port_range * port_range =
  let f = function `List [] -> None
                 | `List [`Int mid]
                   | `Int mid -> Some (mid,mid)
                 | `List [`Int low; `Int high] -> Some (low,high)
                 | _ -> failwith "json ports" in
  function
  | `Assoc ( ["sport_range", sport_rng; "dport_range", dport_rng]
           | ["dport_range", dport_rng; "sport_range", sport_rng])
    -> (f sport_rng, f dport_rng)
  | `Assoc ["sport_range", sport_rng] -> (f sport_rng), None
  | `Assoc ["dport_range", dport_rng] -> None, (f dport_rng)
  | `Assoc [] | `List [] -> None, None
  | _ -> failwith "json broken in parse_ports"

let parse_proto = function
  | `Assoc ["udp", udp_ports ] -> Match_UDP (parse_ports udp_ports)
  | `Assoc ["tcp", tcp_ports ] -> Match_TCP (parse_ports tcp_ports)
  | `Assoc ["icmp", _] -> Match_ICMP
  | `Assoc ["unknown", _] -> Match_Unknown
  | _ -> failwith "json firewall config parse_proto: fail hard"

let parse_conditions lst : 'a =
    List.map (begin function
        | `Assoc ["proto", maybe_proto] -> `Proto (parse_proto maybe_proto)
        | `Assoc ["dst", maybe_addr] -> `Dst (parse_addr maybe_addr)
        | `Assoc ["src", maybe_addr] -> `Src (parse_addr maybe_addr)
        | _ -> failwith "json fw rules: condition must be either 'proto' or 'addr'"
      end) lst

let parse_action : Yojson.Basic.json -> rule = function
  | `Assoc ["accept", `List conditions] ->
    make_condition_match_all (parse_conditions conditions) Accept
  | `Assoc ["nat", `List conditions] ->
    make_condition_match_all (parse_conditions conditions) NAT
  | `Assoc ( ["drop", `List conditions; "reason", `String reason]
           | ["reason", `String reason; "drop", `List conditions])->
    make_condition_match_all (parse_conditions conditions) (drop @@ Some reason)
  | `Assoc ["drop", `List conditions] ->
    make_condition_match_all (parse_conditions conditions) (drop None)
  | `Assoc ( ["nat_to",`List cond; _ ; _ ]
           | [_ ; "nat_to",`List cond ; _]
           | [_ ; _ ; "nat_to",`List cond] as lst ) ->
    make_condition_match_all (parse_conditions cond)
      (nat_to (match List.assoc "host" lst with
           | `String "netvm" -> `NetVM
           | `String "firewall_uplink" -> `Firewall_uplink
           | `String "client_gateway" -> `Client_gateway
           | `String s -> `External (Ipaddr.of_string_exn s))
          (match List.assoc "port" lst with
           | `String i_s -> int_of_string i_s
          )
      )
  | _ -> failwith "json fw rules: unable to parse action"

let parse_json rules_str =
  begin match Yojson.Basic.from_string rules_str with
    | `Assoc ( ["ingress", ingress; "egress",   egress]
             | ["egress", egress  ; "ingress", ingress]) ->
      begin match ingress, egress with
        | `List ing , `List eg ->
          List.map parse_action ing ,
          List.map parse_action eg
      end
    | _ -> failwith "json rules file must be a single object with both 'ingress' and 'egress' keys"
  end


let parse_rules ~(default_ingress : ipv4 action)
                ~(default_egress  : ipv4 action)
                rules_cs_lst : (ruleset * ruleset, [> `Msg of string ]) result =
  Log.app (fun m -> m "Read rule file: %a"
              Format.(pp_print_list Cstruct.hexdump_pp)
              rules_cs_lst) ;
  let ingress_rules, egress_rules =
    parse_json Cstruct.(concat rules_cs_lst |> to_string) in
  let ipv4_from_netvm_rules = {default_action = default_ingress;
                               rules = ingress_rules } in
  let ipv4_from_client_rules = {default_action = default_egress;
                               rules = egress_rules } in
  Ok (ipv4_from_netvm_rules, ipv4_from_client_rules)
