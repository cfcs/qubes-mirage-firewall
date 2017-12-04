(* Copyright (C) 2015, Thomas Leonard <thomas.leonard@unikernel.com>
   See the README file for details. *)

open Fw_utils
open Packet
open Lwt.Infix

let src = Logs.Src.create "firewall" ~doc:"Packet handler"
module Log = (val Logs.src_log src : Logs.LOG)

(* Transmission *)

let transmit_ipv4 packet iface =
  Lwt.catch
    (fun () ->
       let transport = Nat_packet.to_cstruct packet in
       Lwt.catch
         (fun () -> iface#writev Ethif_wire.IPv4 transport)
         (fun ex ->
            Log.warn (fun f -> f "Failed to write packet to %a: %s"
                         Ipaddr.V4.pp_hum iface#other_ip
                         (Printexc.to_string ex));
            Lwt.return ()
         )
    )
    (fun ex ->
       Log.err (fun f -> f "Exception in transmit_ipv4: %s for:@.%a"
                   (Printexc.to_string ex)
                   Nat_packet.pp packet
               );
       Lwt.return ()
    )

let forward_ipv4 t packet =
  let `IPv4 (ip, _) = packet in
  match Router.target t ip with
  | Some iface -> transmit_ipv4 packet iface
  | None -> return ()

(* Packet classification *)

let classify t packet =
  let `IPv4 (ip, transport) = packet in
  let proto =
    match transport with
    | `TCP ({Tcp.Tcp_packet.src_port; dst_port; _}, _) -> `TCP {sport = src_port; dport = dst_port}
    | `UDP ({Udp_packet.src_port; dst_port; _}, _)     -> `UDP {sport = src_port; dport = dst_port}
    | `ICMP _                                          -> `ICMP
  in
  Some {
    packet;
    src = Router.classify t (Ipaddr.V4 ip.Ipv4_packet.src);
    dst = Router.classify t (Ipaddr.V4 ip.Ipv4_packet.dst);
    proto;
  }

let pp_ports fmt {sport; dport} =
  Format.fprintf fmt "sport=%d dport=%d" sport dport

let pp_host fmt = function
  | `Client c -> Ipaddr.V4.pp_hum fmt (c#other_ip)
  | `Unknown_client ip -> Format.fprintf fmt "unknown-client(%a)" Ipaddr.pp_hum ip
  | `NetVM -> Format.pp_print_string fmt "net-vm"
  | `External ip -> Format.fprintf fmt "external(%a)" Ipaddr.pp_hum ip
  | `Firewall_uplink -> Format.pp_print_string fmt "firewall(uplink)"
  | `Client_gateway -> Format.pp_print_string fmt "firewall(client-gw)"

let pp_proto fmt = function
  | `UDP ports -> Format.fprintf fmt "UDP(%a)" pp_ports ports
  | `TCP ports -> Format.fprintf fmt "TCP(%a)" pp_ports ports
  | `ICMP -> Format.pp_print_string fmt "ICMP"
  | `Unknown -> Format.pp_print_string fmt "UnknownProtocol"

let pp_packet fmt {src; dst; proto; packet = _} =
  Format.fprintf fmt "[src=%a dst=%a proto=%a]"
    pp_host src
    pp_host dst
    pp_proto proto

let pp_transport_headers f = function
  | `ICMP (h, _) -> Icmpv4_packet.pp f h
  | `TCP (h, _)  -> Tcp.Tcp_packet.pp f h
  | `UDP (h, _)  -> Udp_packet.pp f h

let pp_header f = function
  | `IPv4 (ip, transport) ->
    Fmt.pf f "%a %a"
      Ipv4_packet.pp ip
      pp_transport_headers transport

(* NAT *)

let translate t packet =
  My_nat.translate t.Router.nat packet

(* Add a NAT rule for the endpoints in this frame, via a random port on the firewall. *)
let add_nat_and_forward_ipv4 t packet =
  let xl_host = t.Router.uplink#my_ip in
  My_nat.add_nat_rule_and_translate t.Router.nat ~xl_host `NAT packet >>= function
  | Ok packet -> forward_ipv4 t packet
  | Error e ->
    Log.warn (fun f -> f "Failed to add NAT rewrite rule: %s (%a)" e pp_header packet);
    Lwt.return ()

(* Add a NAT rule to redirect this conversation to [host:port] instead of us. *)
let nat_to t ~host ~port packet =
  match Router.resolve t host with
  | Ipaddr.V6 _ -> Log.warn (fun f -> f "Cannot NAT with IPv6"); Lwt.return ()
  | Ipaddr.V4 target ->
    let xl_host = t.Router.uplink#my_ip in
    My_nat.add_nat_rule_and_translate t.Router.nat ~xl_host (`Redirect (target, port)) packet >>= function
    | Ok packet -> forward_ipv4 t packet
    | Error e ->
      Log.warn (fun f -> f "Failed to add NAT redirect rule: %s (%a)" e pp_header packet);
      Lwt.return ()

(* Handle incoming packets *)

let apply_rules t (context:[>]) (info:Packet.info) =
  Rules.apply_rules ~default_action:(fun (_,_)-> return ())
    Rules.[
      begin function
      | `Accept, {dst = `Client client_link ; _} ->
        Action (fun (_, {packet;_}) -> transmit_ipv4 packet client_link)
      | `Accept, {dst = (`External _ | `NetVM) ; _} ->
        Action (function _, {packet;_} -> transmit_ipv4 packet t.Router.uplink)
      | `Accept, {dst = (`Firewall_uplink | `Client_gateway); _} ->
        Action (function _, (info:Packet.info) ->
              Log.warn (fun f ->
                f "Bad rule: firewall can't accept packets %a" pp_packet info);
              return ()
          )
      | `NAT, _ ->
        Action (function _, {packet;_} -> add_nat_and_forward_ipv4 t packet)
      | `NAT_to (host, port), _ ->
        Action (function _, {packet;_}-> nat_to t packet ~host ~port)
      | `Drop reason, _ ->
        Action (function _, _ ->
            Log.info (fun f -> f "Dropped packet (%s) %a"
                         reason pp_packet info);
            return () )
      | _-> No_decision
        end
    ]
    (context,info)
  |> fun handle ->
  handle (context,info)

let handle_low_memory t =
  match Memory_pressure.status () with
  | `Memory_critical -> (* TODO: should happen before copying and async *)
      Log.warn (fun f -> f "Memory low - dropping packet and resetting NAT table");
      My_nat.reset t.Router.nat >|= fun () ->
      `Memory_critical
  | `Ok -> Lwt.return `Ok

let ipv4_from_client t packet =
  handle_low_memory t >>= function
  | `Memory_critical -> return ()
  | `Ok ->
  (* Check for existing NAT entry for this packet *)
  translate t packet >>= function
  | Some frame -> forward_ipv4 t frame  (* Some existing connection or redirect *)
  | None ->
  (* Decide what to do with a packet from a client VM.
     Note: If the packet matched an existing NAT rule then this isn't called. *)
  let from_client = function
  | { dst = (`External _ | `NetVM); _ } -> `NAT
  | { dst = `Client_gateway; proto = `UDP { dport = 53; _ }; _ } ->
    `NAT_to (`NetVM, 53)
  | { dst = (`Client_gateway | `Firewall_uplink); _ } ->
    `Drop "packet addressed to firewall itself"
  | { dst = `Client _ ; _} -> `Drop "prevent communication between client VMs"
  in
  (* No existing NAT entry. Check the firewall rules. *)
  match classify t packet with
  | None -> return ()
  | Some info -> apply_rules t (from_client info) info

let ipv4_from_netvm t packet =
  handle_low_memory t >>= function
  | `Memory_critical -> return ()
  | `Ok ->
  match classify t packet with
  | None -> return ()
  | Some info ->
  match info.src with
  | `Client _ | `Firewall_uplink | `Client_gateway ->
    Log.warn (fun f -> f "Frame from NetVM has internal source IP address! %a" pp_packet info);
    return ()
  | `External _ | `NetVM ->
  translate t packet >>= function
  | Some frame -> forward_ipv4 t frame
  | None ->
  (* Decide what to do with a packet received from the outside world.
     Note: If the packet matched an existing NAT rule then this isn't called. *)
  let from_netvm = function
      | _ -> `Drop "drop by default"
  in
  apply_rules t (from_netvm info) info
