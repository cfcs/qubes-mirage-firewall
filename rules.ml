(* Copyright (C) 2015, Thomas Leonard <thomas.leonard@unikernel.com>
   See the README file for details. *)

(** Put your firewall rules here. *)

type ('input, 'return) callback = 'input -> 'return

type ('input,'return) decision =
  | Action of ('input,'return) callback
    (* "Stop parsing and definitely call my callback on this" *)
  | No_decision (* "I'm OK with this, check the other rules" *)

type ('input, 'return) rule =
  'input -> ('input, 'return) decision (* functional firewall, no state!!*)

type ('input,'return) ruleset = ('input, 'return) rule list

let src = Logs.Src.create "firewall" ~doc:"Rules parser"
module Log = (val Logs.src_log src : Logs.LOG)

let parse_rules (type input) (type return)
    ~(default_action:(input,return) callback) rules_cs_lst :
  ((input, return) ruleset, [> `Msg of string ]) result =
  Log.info (fun m -> m "Read rule file: %S"
               (Cstruct.(to_string (concat rules_cs_lst)))) ;
  Ok [fun _ -> Action default_action]

let apply_rules (type input) (type return)
    ~(default_action : (input,return) callback)
    (ruleset : (input, return) ruleset)
    (packet:input)
  : (input,return) callback =
  List.fold_left
    (function
      | (Action _) as decision -> fun _ignored_rule -> decision
      | No_decision -> fun check -> check packet
    ) No_decision ruleset
  |> function
  | No_decision -> default_action
  | Action f -> f

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
