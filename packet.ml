(* Copyright (C) 2015, Thomas Leonard <thomas.leonard@unikernel.com>
   See the README file for details. *)

open Fw_utils

type port = int

type ports = {
  sport : port; (* Source port *)
  dport : port; (* Destination *)
}

type host =
  [ `Client_gateway
  | `Firewall_uplink
  | `NetVM
  | `Client of client_link
  | `External of Ipaddr.t ]


type proto = [ `UDP of ports | `TCP of ports | `ICMP | `Unknown ]

type info = {
  packet : Nat_packet.t;
  src : host;
  dst : host;
  proto : proto;
}
