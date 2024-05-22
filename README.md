# Exemple de folosire a aplicației ovn-trace

În cele ce urmează vom prezenta un exemplu de folosire a aplicației `ovn-trace` pentru a urmări traficul ce trece printr-un SDN bazat pe OVN, într-un cloud de tip OpenStack. Scenariile ce le vom discuta sunt următoarele:

* **Cazul 1**: O mașină virtuală care trimite trafic către internet printr-un provider network, iar security group-urile sunt configurate corespunzător.
* **Cazul 2**: O mașină virtuală care trimite trafic către internet printr-un provider network, însă cu un security group care blochează traficul pe anumite porturi.



## Context

Aplicația `ovn-trace` se folosește de informațiile prezente in controllerul OVN pentru a simula traseul pe care un pachet îl parcurge în rețeaua SDN. Acest lucru este posibil deoarece toate informațiile pe baza cărora soluția de SDN ia decizii sunt stocate într-o bază de date centralizată, iar controllerele OVN crează reguli de tip OpenFlow ce sunt mai apoi propagate către switch-urile OVS.

Astfel, aplicația `ovn-trace` poate să aplice aceleași reguli pentru a determina cu exactitate traseul pe care un pachet îl va lua, în funcție de regulile ce sunt definite în rețeaua SDN, dar și în funcție de parametrii pe care noi îi furnizăm.

## Cazul 1

În cazul 1 vom simula un pachet ICMP de la un VM numit `jammy-test` conectat la o rețea numită `int-net`, către un IP de pe internet (`8.8.8.8`). Vom simula de asemenea și un pachet TCP de la același VM către același IP, pe portul 80.

Pentru a putea să simulăm traseul dorit, trebuie să colectăm informațiile necesare pentru redactarea comenzii `ovn-trace`. Această procedură poate să difere în funcție de caz. Pentru cazul 1, vom avea nevoie de următoarele informații:

* ID-ul rețelei la care este conectată mașina virtuală.
* IP-ul setat pe NIC-ul mașinii virtuale care trimite traficul către internet. Este vorba de IP-ul privat din rețeaua a cărui ID am preluat, nu de floating IP.
* ID-ul portului atașat la mașina virtuală.
* Adresa MAC a NIC-ului atașat la mașina virtuală.
* Adresa MAC a default gateway-ului setat pe rețeaua la care este conectată mașina virtuală.
* Adresa IP destinație și un port pe care mașina virtuală încearcă să-l acceseze.

Acesta va fi cazul favorabil, în care mașina virtuală are conectivitate către internet, iar totul funcționează.

### Pasul 1: Colectarea informațiilor necesare

* Preluăm ID-ul rețelei la care este conectată mașina virtuală:

```bash
gabriel@arrakis:~$ openstack server show jammy-test -c addresses
+-----------+-------------------------------------+
| Field     | Value                               |
+-----------+-------------------------------------+
| addresses | int-net=10.8.21.212, 192.168.222.40 |
+-----------+-------------------------------------+
```

Observăm că mașina virtuală `jammy-test` este conectată la rețeaua `int-net`, iar IP-ul său este `192.168.222.40`. IP-ul `10.8.21.212` este un floating IP asociat acestui VM, ce face NAT către `192.168.222.40`

* Preluăm ID-ul rețelei `int-net`:

```bash
gabriel@arrakis:~$ openstack network show int-net -c id
+-------+--------------------------------------+
| Field | Value                                |
+-------+--------------------------------------+
| id    | 8e486692-3b40-4875-8243-052b5baf31a6 |
+-------+--------------------------------------+
```

* Preluăm ID-ul portului, adresa MAC a NIC-ului și adresa IP a mașinii virtuale:

```bash
gabriel@arrakis:~$ openstack port list --server jammy-test
+--------------------------------------+------+-------------------+-------------------------------------------------------------------------------+--------+
| ID                                   | Name | MAC Address       | Fixed IP Addresses                                                            | Status |
+--------------------------------------+------+-------------------+-------------------------------------------------------------------------------+--------+
| e4f83d35-baad-41b3-af74-853dc6d308bd |      | fa:16:3e:0a:76:09 | ip_address='192.168.222.40', subnet_id='7a5059b0-7960-4862-90f1-ab41cc73cdcb' | ACTIVE |
+--------------------------------------+------+-------------------+-------------------------------------------------------------------------------+--------+
```

Observăm că ID-ul portului este `e4f83d35-baad-41b3-af74-853dc6d308bd`, adresa MAC a NIC-ului este `fa:16:3e:0a:76:09`, iar adresa IP a mașinii virtuale este `192.168.222.40`. Observăm de asemenea că ID-ul subnetului este `7a5059b0-7960-4862-90f1-ab41cc73cdcb`.

* Preluăm adresa MAC a default gateway-ului setat pe rețeaua la care este conectată mașina virtuală. Pentru aceasta, vom folosi ID-ul subnetului:

```bash
gabriel@arrakis:~$ openstack port list --fixed-ip subnet=7a5059b0-7960-4862-90f1-ab41cc73cdcb --device-owner network:router_interface
+--------------------------------------+------+-------------------+------------------------------------------------------------------------------+--------+
| ID                                   | Name | MAC Address       | Fixed IP Addresses                                                           | Status |
+--------------------------------------+------+-------------------+------------------------------------------------------------------------------+--------+
| 05a05227-5ad2-4915-a4e3-0f81cafc9965 |      | fa:16:3e:36:fe:cd | ip_address='192.168.222.1', subnet_id='7a5059b0-7960-4862-90f1-ab41cc73cdcb' | ACTIVE |
+--------------------------------------+------+-------------------+------------------------------------------------------------------------------+--------+
```

Observăm că adresa MAC a default gateway-ului este `fa:16:3e:36:fe:cd`.

Deci în cazul de față datele sunt:

* ID-ul rețelei `int-net`: `8e486692-3b40-4875-8243-052b5baf31a6`
* ID-ul portului: `e4f83d35-baad-41b3-af74-853dc6d308bd`
* IP-ul mașinii virtuale: `192.168.222.40`
* MAC-ul mașinii virtuale: `fa:16:3e:0a:76:09`
* Adresa MAC a default gateway-ului: `fa:16:3e:36:fe:cd`
* Adresa IP destinație: `8.8.8.8`

Accesăm unul din nodurile `ovn-central` sau oricare nod care are instalat `ovn-trace` și are acces la controllerul OVN.

### Pasul 2: Rularea comenzii `ovn-trace`

După cum am menționat mai sus, aplicația `ovn-trace` se conectează la controllerul OVN. Pentru a reduce din numărul de parametrii pe care trebuie să îi furnizăm, vom crea un alias pentru a specifica controllerul OVN la care ne conectăm:

```bash
alias ovn-trace="ovn-trace --db=ssl:10.0.9.127:16642,ssl:10.0.9.42:16642,ssl:10.0.9.69:16642 -c /etc/ovn/cert_host -C /etc/ovn/ovn-central.crt -p /etc/ovn/key_host"
```

Cele 3 IP-uri sunt IP-urile nodurilor ce rulează `ovn-central`. Accesul este pe bază de certificat x509 client. Acestea fiind setate, putem să continuăm cu rularea comenzii `ovn-trace`.

Vom simula mai întâi traseul unui pachet ICMP de la mașina virtuală `jammy-test` către IP-ul `8.8.8.8`:

```bash
ovn-trace --ovs neutron-8e486692-3b40-4875-8243-052b5baf31a6 \
    'inport=="e4f83d35-baad-41b3-af74-853dc6d308bd" &&
    eth.src==fa:16:3e:0a:76:09 &&
    ip4.src==192.168.222.40 &&
    eth.dst==fa:16:3e:36:fe:cd &&
    ip4.dst==8.8.8.8 &&
    icmp4.type==8 &&
    ip.ttl == 64' | grep -v cookie
```

Ceea ce va genera următorul output:

```bash
# icmp,reg14=0x6,vlan_tci=0x0000,dl_src=fa:16:3e:0a:76:09,dl_dst=fa:16:3e:36:fe:cd,nw_src=192.168.222.40,nw_dst=8.8.8.8,nw_tos=0,nw_ecn=0,nw_ttl=64,nw_frag=no,icmp_type=8,icmp_code=0

ingress(dp="int-net", inport="e4f83d")
--------------------------------------
 0. ls_in_check_port_sec (northd.c:8588): 1, priority 50, uuid 0b0cf77b
    reg0[15] = check_in_port_sec();
    next;
 4. ls_in_pre_acl (northd.c:5994): ip, priority 100, uuid 497a3dc7
    reg0[0] = 1;
    next;
 6. ls_in_pre_stateful (northd.c:6212): reg0[0] == 1, priority 100, uuid dad17c7d
    ct_next;

ct_next(ct_state=est|trk /* default (use --ct to customize) */)
---------------------------------------------------------------
 7. ls_in_acl_hint (northd.c:6300): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid 74203d1c
    reg0[8] = 1;
    reg0[10] = 1;
    next;
 8. ls_in_acl_eval (northd.c:6518): reg0[8] == 1 && (inport == @pg_beb6f07a_ca99_4b62_abb6_d381da4930f4 && ip4), priority 2002, uuid f75b4149
    reg8[16] = 1;
    next;
 9. ls_in_acl_action (northd.c:6730): reg8[16] == 1, priority 1000, uuid 024035a2
    reg8[16] = 0;
    reg8[17] = 0;
    reg8[18] = 0;
    next;
19. ls_in_acl_after_lb_action (northd.c:6756): 1, priority 0, uuid 96976122
    reg8[16] = 0;
    reg8[17] = 0;
    reg8[18] = 0;
    next;
27. ls_in_l2_lkup (northd.c:9414): eth.dst == fa:16:3e:36:fe:cd, priority 50, uuid f6a86a36
    outport = "05a052";
    output;

egress(dp="int-net", inport="e4f83d", outport="05a052")
-------------------------------------------------------
 0. ls_out_pre_acl (northd.c:5881): ip && outport == "05a052", priority 110, uuid e2f8fef2
    next;
 1. ls_out_pre_lb (northd.c:5881): ip && outport == "05a052", priority 110, uuid c6bf12fa
    next;
 3. ls_out_acl_hint (northd.c:6300): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid 23ca1ca8
    reg0[8] = 1;
    reg0[10] = 1;
    next;
 5. ls_out_acl_action (northd.c:6756): 1, priority 0, uuid 5727ef50
    reg8[16] = 0;
    reg8[17] = 0;
    reg8[18] = 0;
    next;
 9. ls_out_check_port_sec (northd.c:5846): 1, priority 0, uuid 8d6dc6b2
    reg0[15] = check_out_port_sec();
    next;
10. ls_out_apply_port_sec (northd.c:5851): 1, priority 0, uuid 74c5f950
    output;
    /* output to "05a052", type "patch" */

ingress(dp="router", inport="lrp-05a052")
-----------------------------------------
 0. lr_in_admission (northd.c:11779): eth.dst == fa:16:3e:36:fe:cd && inport == "lrp-05a052", priority 50, uuid 70ff7c1e
    xreg0[0..47] = fa:16:3e:36:fe:cd;
    next;
 1. lr_in_lookup_neighbor (northd.c:11963): 1, priority 0, uuid 3df83e10
    reg9[2] = 1;
    next;
 2. lr_in_learn_neighbor (northd.c:11972): reg9[2] == 1 || reg9[3] == 0, priority 100, uuid 2431ee5e
    next;
12. lr_in_ip_routing_pre (northd.c:12197): 1, priority 0, uuid d623d6b4
    reg7 = 0;
    next;
13. lr_in_ip_routing (northd.c:10602): reg7 == 0 && ip4.dst == 0.0.0.0/0, priority 1, uuid fc0bc09f
    ip.ttl--;
    reg8[0..15] = 0;
    reg0 = 10.8.21.1;
    reg1 = 10.8.21.214;
    eth.src = fa:16:3e:3e:b0:35;
    outport = "lrp-06bc20";
    flags.loopback = 1;
    next;
14. lr_in_ip_routing_ecmp (northd.c:12292): reg8[0..15] == 0, priority 150, uuid 98bc748d
    next;
15. lr_in_policy (northd.c:12457): 1, priority 0, uuid f98f0c44
    reg8[0..15] = 0;
    next;
16. lr_in_policy_ecmp (northd.c:12459): reg8[0..15] == 0, priority 150, uuid b7b2acc7
    next;
17. lr_in_arp_resolve (northd.c:12493): ip4, priority 1, uuid a2978ce1
    get_arp(outport, reg0);
    /* MAC binding to 00:e0:67:2c:cc:2e. */
    next;
20. lr_in_gw_redirect (northd.c:14748): ip4.src == 192.168.222.40 && outport == "lrp-06bc20" && is_chassis_resident("e4f83d"), priority 100, uuid 1d3f4912
    eth.src = fa:16:3e:c0:63:5e;
    reg1 = 10.8.21.212;
    next;
21. lr_in_arp_request (northd.c:13104): 1, priority 0, uuid 714b1003
    output;

egress(dp="router", inport="lrp-05a052", outport="lrp-06bc20")
--------------------------------------------------------------
 0. lr_out_chk_dnat_local (northd.c:14464): 1, priority 0, uuid ba6b8261
    reg9[4] = 0;
    next;
 1. lr_out_undnat (northd.c:13988): ip && ip4.src == 192.168.222.40 && outport == "lrp-06bc20", priority 100, uuid 246cdef7
    eth.src = fa:16:3e:c0:63:5e;
    ct_dnat;

ct_dnat /* assuming no un-dnat entry, so no change */
-----------------------------------------------------
 3. lr_out_snat (northd.c:14196): ip && ip4.src == 192.168.222.40 && outport == "lrp-06bc20" && is_chassis_resident("e4f83d") && (!ct.trk || !ct.rpl), priority 161, uuid 5880ef61
    eth.src = fa:16:3e:c0:63:5e;
    ct_snat(10.8.21.212);

ct_snat(ip4.src=10.8.21.212)
----------------------------
 6. lr_out_delivery (northd.c:13150): outport == "lrp-06bc20", priority 100, uuid be4b1621
    output;
    /* output to "lrp-06bc20", type "patch" */

ingress(dp="ext-net", inport="06bc20")
--------------------------------------
 0. ls_in_check_port_sec (northd.c:8588): 1, priority 50, uuid 0b0cf77b
    reg0[15] = check_in_port_sec();
    next;
 5. ls_in_pre_lb (northd.c:5878): ip && inport == "06bc20", priority 110, uuid c333d0db
    next;
27. ls_in_l2_lkup (northd.c:8530): 1, priority 0, uuid 74c652a7
    outport = get_fdb(eth.dst);
    next;
28. ls_in_l2_unknown (northd.c:8534): outport == "none", priority 50, uuid c1edd421
    outport = "_MC_unknown";
    output;

multicast(dp="ext-net", mcgroup="_MC_unknown")
----------------------------------------------

    egress(dp="ext-net", inport="06bc20", outport="provnet-c05c72")
    ---------------------------------------------------------------
         1. ls_out_pre_lb (northd.c:5881): ip && outport == "provnet-c05c72", priority 110, uuid 601ba5ad
            ct_clear;
            next;
         9. ls_out_check_port_sec (northd.c:5846): 1, priority 0, uuid 8d6dc6b2
            reg0[15] = check_out_port_sec();
            next;
        10. ls_out_apply_port_sec (northd.c:5851): 1, priority 0, uuid 74c5f950
            output;
            /* output to "provnet-c05c72", type "localnet" */
```

Putem să observăm traseul pachetului prin infrastructura virtuală, începând de la portul de intrare al rețelei `int-net` (`e4f83d`) atașat la VM, trecând prin routerul `router` via `05a052` (portul asociat default GW preluat mai sus) unde se produce translatarea NAT (`06bc20`) și ajungând la portul de ieșire al rețelei `ext-net` (`provnet-c05c72`).

Cu excepția `provnet-c05c72`, care corespunde cu portul fizic efectiv, celelalte ID-uri abreviate corespund cu porturi logice ce se regăsesc și in Neutron:

* `e4f83d` (`e4f83d35-baad-41b3-af74-853dc6d308bd`) - este portul VM-ului preluat la inceputul exemplului
* `05a052` (`05a05227-5ad2-4915-a4e3-0f81cafc9965`) - este portul default GW preluat la inceputul exemplului
* `lrp-06bc20` - este portul de ieșire al routerului `router` unde se face translatarea NAT. `lrp` vine de la `logical router port`. ID-ul poate fi găsit folosind comanda:

```bash
gabriel@arrakis:~$ openstack port list --long| grep 06bc20
| 06bc20a7-6411-42ae-9c5d-6bffadedf3ff |      | fa:16:3e:3e:b0:35 | ip_address='10.8.21.214', subnet_id='7614d8d4-6834-49a7-b7b0-4af19f306fc9'    | DOWN   | None            | network:router_gateway   |      |
```

Observăm că portul este de tip `network:router_gateway`, deci este un port de ieșire al unui router, iar adresa IP asociată este IP-ul public al routerului. În lipsa unui floating IP asociat VM-ului, aceasta va fi adresa prin care pachetul va ieși pe internet.

Este important de reținut acest aspect pentru ultimul pas.

Dacă `ovn-trace` ne indică faptul că pachetul ar trebui să ajungă pe fir (cum observăm mai sus), însă acest lucru nu se întâmplă, atunci trebuie să verificăm dacă într-adevăr pachetul este sau nu pus pe fir. Cu informațiile de mai sus, putem să determinăm punctul de ieșire din SDN și să verificăm dacă pachetul ajunge acolo.

În output-ul de mai sus, observăm la final că pachetul intră pe chassis gateway prin portul `06bc20` și este trimis către portul `provnet-c05c72`:

```bash
egress(dp="ext-net", inport="06bc20", outport="provnet-c05c72")
```

Pentru a putea să inspectăm traficul pe fir când iese din SDN, trebuie să accesăm nodul fizic și să folosim `tcpdump` sau `wireshark` pentru a inspecta pachetele. Dar înainte de asta, trebuie să determinăm nodul fizic pe care se află portul `06bc20`:

```bash
:~# ovn-sbctl list Port_Binding 06bc20
_uuid               : 14c6410e-2749-4aa1-9dce-fcc6463aec7a
additional_chassis  : []
additional_encap    : []
chassis             : []
datapath            : f00b6348-e37d-42e9-89e8-403661dd419d
encap               : []
external_ids        : {"neutron:cidrs"="10.8.21.214/24", "neutron:device_id"="0b41b56f-b961-4540-aeb2-bdec4e91de38", "neutron:device_owner"="network:router_gateway", "neutron:network_name"=neutron-a65cd8ba-4d81-427a-aa0a-ef727f2cec21, "neutron:port_capabilities"="", "neutron:port_name"="", "neutron:project_id"="", "neutron:revision_number"="1", "neutron:security_group_ids"="", "neutron:subnet_pool_addr_scope4"="", "neutron:subnet_pool_addr_scope6"="", "neutron:vnic_type"=normal}
gateway_chassis     : []
ha_chassis_group    : []
logical_port        : "06bc20a7-6411-42ae-9c5d-6bffadedf3ff"
mac                 : [router]
mirror_rules        : []
nat_addresses       : ["fa:16:3e:0c:b5:77 10.8.21.250 is_chassis_resident(\"2d6d8350-f2f2-4499-ad04-670b0f59e0c6\")", "fa:16:3e:3e:b0:35 10.8.21.214 is_chassis_resident(\"cr-lrp-06bc20a7-6411-42ae-9c5d-6bffadedf3ff\")", "fa:16:3e:c0:63:5e 10.8.21.212 is_chassis_resident(\"e4f83d35-baad-41b3-af74-853dc6d308bd\")", "fa:16:3e:e5:ab:c8 10.8.21.228 is_chassis_resident(\"adec6e88-5765-44e5-8987-9ead58b1697e\")"]
options             : {peer=lrp-06bc20a7-6411-42ae-9c5d-6bffadedf3ff}
parent_port         : []
port_security       : []
requested_additional_chassis: []
requested_chassis   : []
tag                 : []
tunnel_key          : 3
type                : patch
up                  : false
virtual_parent      : []

```

Observăm că pentru portul `06bc20` in câmpul `nat_addresses` avem un câmp:


```bash
"fa:16:3e:c0:63:5e 10.8.21.212 is_chassis_resident(\"e4f83d35-baad-41b3-af74-853dc6d308bd\")"
```

Această mapare ne spune că traficul spre exterior va trece prin floating IP-ul asociat acestui VM, iar portul pe care este instalat ARP responder-ul pentru acest FIP este instalat pe portul `e4f83d35-baad-41b3-af74-853dc6d308bd`. Verificăm unde este `Port_binding` făcut pentru acest port:

```bash
[root@osp-node-1 /]# ovn-sbctl list Port_Binding e4f83d35-baad-41b3-af74-853dc6d308bd
_uuid               : 5969bc5d-4a87-4741-bf6b-5ce94df1190a
additional_chassis  : []
additional_encap    : []
chassis             : b3cdf636-32bb-445d-8ed1-581449d66e19
datapath            : 513f073e-b633-46ad-aeae-eebf69abf25f
encap               : []
external_ids        : {"neutron:cidrs"="192.168.222.40/24", "neutron:device_id"="aba6a3fa-578b-44a0-bcbc-fcc131987e6a", "neutron:device_owner"="compute:nova", "neutron:host_id"=osp-node-1, "neutron:network_name"=neutron-8e486692-3b40-4875-8243-052b5baf31a6, "neutron:port_capabilities"="", "neutron:port_fip"="10.8.21.212", "neutron:port_name"="", "neutron:project_id"=b8af9ef5cefd45989443e5d2caceab2c, "neutron:revision_number"="4", "neutron:security_group_ids"="beb6f07a-ca99-4b62-abb6-d381da4930f4", "neutron:subnet_pool_addr_scope4"="", "neutron:subnet_pool_addr_scope6"="", "neutron:vnic_type"=normal}
gateway_chassis     : []
ha_chassis_group    : []
logical_port        : "e4f83d35-baad-41b3-af74-853dc6d308bd"
mac                 : ["fa:16:3e:0a:76:09 192.168.222.40"]
mirror_rules        : []
nat_addresses       : []
options             : {requested-chassis=osp-node-1}
parent_port         : []
port_security       : ["fa:16:3e:0a:76:09 192.168.222.40"]
requested_additional_chassis: []
requested_chassis   : b3cdf636-32bb-445d-8ed1-581449d66e19
tag                 : []
tunnel_key          : 6
type                : ""
up                  : true
virtual_parent      : []
```

observăm că acest port este instalat pe nodul `osp-node-1`. Deci, pentru a inspecta traficul, accesăm nodul `osp-node-1` și rulăm `tcpdump` pentru a inspecta pachetele. Pe nodul fizic, verificăm portul folosit in bridge-ul extern ce corespunde `provnet-c05c72`:

```bash
[root@osp-node-1 ~]# ovs-vsctl show
d0d52f0d-b184-4223-a8a5-a6a79bd178f2
    Manager "ptcp:6640:127.0.0.1"
        is_connected: true
    Bridge br-ex
        fail_mode: standalone
        Port patch-provnet-c05c72ee-25e4-41a8-b21d-b23be5ee2dc9-to-br-int
            Interface patch-provnet-c05c72ee-25e4-41a8-b21d-b23be5ee2dc9-to-br-int
                type: patch
                options: {peer=patch-br-int-to-provnet-c05c72ee-25e4-41a8-b21d-b23be5ee2dc9}
        Port vlan21
            tag: 21
            Interface vlan21
                type: internal
        Port vlan20
            tag: 20
            Interface vlan20
                type: internal
        Port vlan22
            tag: 22
            Interface vlan22
                type: internal
        Port enp1s0
            Interface enp1s0
        Port br-ex
            Interface br-ex
                type: internal
    Bridge br-floating
        Port patch-br-floating_osp-node-1.lab.ocp.lan-to-br-int
            Interface patch-br-floating_osp-node-1.lab.ocp.lan-to-br-int
                type: patch
                options: {peer=patch-br-int-to-br-floating_osp-node-1.lab.ocp.lan}
        Port br-floating
            Interface br-floating
                type: internal
        Port enp9s0
            Interface enp9s0
    Bridge br-int
        fail_mode: secure
        datapath_type: system
        Port tape4f83d35-ba
            Interface tape4f83d35-ba
        Port ovn-312383-0
            Interface ovn-312383-0
                type: geneve
                options: {csum="true", key=flow, remote_ip="172.19.0.30"}
        Port ovn-c398f0-0
            Interface ovn-c398f0-0
                type: geneve
                options: {csum="true", key=flow, remote_ip="172.19.0.102"}
                bfd_status: {diagnostic="No Diagnostic", flap_count="0", forwarding="false", remote_diagnostic="No Diagnostic", remote_state=down, state=down}
        Port tap8e486692-30
            Interface tap8e486692-30
        Port br-int
            Interface br-int
                type: internal
        Port patch-br-int-to-provnet-c05c72ee-25e4-41a8-b21d-b23be5ee2dc9
            Interface patch-br-int-to-provnet-c05c72ee-25e4-41a8-b21d-b23be5ee2dc9
                type: patch
                options: {peer=patch-provnet-c05c72ee-25e4-41a8-b21d-b23be5ee2dc9-to-br-int}
        Port ovn-476efb-0
            Interface ovn-476efb-0
                type: geneve
                options: {csum="true", key=flow, remote_ip="172.19.0.101"}
                bfd_status: {diagnostic="No Diagnostic", flap_count="0", forwarding="false", remote_diagnostic="No Diagnostic", remote_state=down, state=down}
        Port ovn-387836-0
            Interface ovn-387836-0
                type: geneve
                options: {csum="true", key=flow, remote_ip="172.19.0.31"}
        Port ovn-056a42-0
            Interface ovn-056a42-0
                type: geneve
                options: {csum="true", key=flow, remote_ip="172.19.0.32"}
        Port patch-br-int-to-br-floating_osp-node-1.lab.ocp.lan
            Interface patch-br-int-to-br-floating_osp-node-1.lab.ocp.lan
                type: patch
                options: {peer=patch-br-floating_osp-node-1.lab.ocp.lan-to-br-int}
    ovs_version: "3.1.5"
```

Observăm că in `br-ex` avem portul fizic `enp1s0`.

Știm că trimitem pachete ICMP către `8.8.8.8`. Știm de asemenea că pentru a ajunge pe internet, se face NAT de la IP-ul privat al VM-ului către IP-ul "public" `10.8.21.212`.

Verificăm dacă provnet are un VLAN asociat:

```bash
[root@osp-node-1 /]# ovn-nbctl --db=tcp:ovsdbserver-nb.openstack.svc:6641 list Logical_Switch_Port provnet-c05c72ee-25e4-41a8-b21d-b23be5ee2dc9 | grep "tag "
tag                 : 1000
```

Observăm că are tag 1000 asociat rețelei. Ar trebui să coincidă cu "segmentation ID" setat in OpenStack.

Rulăm tcpdump:

```bash
[root@osp-node-1 ~]# tcpdump -nei enp1s0 "vlan 1000 and icmp and host 10.8.21.212"
dropped privs to tcpdump
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on enp1s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

Accesăm VM-ul și rulăm `ping`. E important de ținut minte că `ovn-trace` nu generează trafic efectiv. Doar simuleaza trafic bazat pe regulile openflow prezente in OVN.

Dacă totul functionează corect, vom vedea pachetele ICMP trimise de VM către destinație, precum și răspunsurile de la destinație.

Dacă nu vedem pachete că pleacă din SDN, există posibilitatea să existe o problema la nivel fizic a rețelei ce asigură traficul între nodurile ce participă la SDN.

Dacă vedem că pleacă pe fir pachetele ICMP, însă nu vin răpunsuri, atunci problema este probabil una de rutare, după ce pachetul iese din SDN, iar soluția espe probabil pe gateway-ul upstream.

Exemplu cu ping:

```bash
[root@osp-node-1 ~]# tcpdump -nei enp1s0 "vlan 1000 and icmp and host 10.8.21.212"
dropped privs to tcpdump
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on enp1s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
12:03:26.539511 fa:16:3e:c0:63:5e > 00:e0:67:2c:cc:2e, ethertype 802.1Q (0x8100), length 102: vlan 1000, p 0, ethertype IPv4 (0x0800), 10.8.21.212 > 8.8.8.8: ICMP echo request, id 5, seq 271, length 64
12:03:26.547880 00:e0:67:2c:cc:2e > fa:16:3e:c0:63:5e, ethertype 802.1Q (0x8100), length 102: vlan 1000, p 0, ethertype IPv4 (0x0800), 8.8.8.8 > 10.8.21.212: ICMP echo reply, id 5, seq 271, length 64
```

Observăm pachetele generate.

Pentru a testa conectivitatea către portul 80, comanda `ovn-trace` va fi similară cu cea de mai sus, cu excepția faptului că vom schimba portul ICMP cu portul 80:

```bash
ovn-trace --ovs neutron-8e486692-3b40-4875-8243-052b5baf31a6 \ 
    'inport=="e4f83d35-baad-41b3-af74-853dc6d308bd" &&
    eth.src==fa:16:3e:0a:76:09 &&
    ip4.src==192.168.222.40 &&
    eth.dst==fa:16:3e:36:fe:cd &&
    ip4.dst==8.8.8.8 &&
    tcp.dst==22 &&
    ip.ttl == 255'
```

Observăm că au fost schimbate următoarele:

* `icmp.type==8` a fost schimbat cu `tcp.dst==22`
* `ip.ttl==64` a fost schimbat cu `ip.ttl==255`

Rezultatul comenzii este asemănător cu rezultatul obținut pentru ICMP.


## Cazul 2

În cazul 2 vom folosi același VM însă vom modifica security group-ul să nu permita accesul pe portul 80 "egress".

Preluăm proiectul și security group-ul setat pe VM-ul `jammy-test`:

```bash
gabriel@arrakis:~$ openstack server show jammy-test -c security_groups -c project_id
+-----------------+----------------------------------+
| Field           | Value                            |
+-----------------+----------------------------------+
| project_id      | b8af9ef5cefd45989443e5d2caceab2c |
| security_groups | name='test-sg'                   |
+-----------------+----------------------------------+
```

Preluăm ID-ul security group-ului `test-sg`:

```bash
gabriel@arrakis:~$ openstack security group show test-sg -c id
+-------+--------------------------------------+
| Field | Value                                |
+-------+--------------------------------------+
| id    | beb6f07a-ca99-4b62-abb6-d381da4930f4 |
+-------+--------------------------------------+
```

Verificăm regulile setate pe security group-ul `test-sg`:

```bash
gabriel@arrakis:~$ openstack security group rule list --egress beb6f07a-ca99-4b62-abb6-d381da4930f4
+--------------------------------------+-------------+-----------+-----------+------------+-----------+-----------------------+----------------------+
| ID                                   | IP Protocol | Ethertype | IP Range  | Port Range | Direction | Remote Security Group | Remote Address Group |
+--------------------------------------+-------------+-----------+-----------+------------+-----------+-----------------------+----------------------+
| 0631afec-9577-41f4-8084-2ccf794540d3 | None        | IPv6      | ::/0      |            | egress    | None                  | None                 |
| 96658621-42a1-4aac-aedb-42b3a869bb0c | None        | IPv4      | 0.0.0.0/0 |            | egress    | None                  | None                 |
+--------------------------------------+-------------+-----------+-----------+------------+-----------+-----------------------+----------------------+
```

Înainte să ștergem regula ce permite accesul `egress` că

Ștergem regula egress implicită ce permite traficul pe orice port:

```bash
gabriel@arrakis:~$ openstack security group rule delete 96658621-42a1-4aac-aedb-42b3a869bb0c
```

Fără această regulă, nici un fel de trafic nu va mai fi permis pe ipv4 spre exterior. Rulăm din nou comanda `ovn-trace` pentru a vedea ce se întâmplă:

```bash
[root@osp-node-1 /]# ovn-trace --ovs neutron-8e486692-3b40-4875-8243-052b5baf31a6 'inport=="e4f83d35-baad-41b3-af74-853dc6d308bd" &&
    eth.src==fa:16:3e:0a:76:09 &&
    ip4.src==192.168.222.40 &&
    eth.dst==fa:16:3e:36:fe:cd &&
    ip4.dst==8.8.8.8 &&
    tcp.dst==22 &&
    ip.ttl == 255'| grep -v cookie
# tcp,reg14=0x6,vlan_tci=0x0000,dl_src=fa:16:3e:0a:76:09,dl_dst=fa:16:3e:36:fe:cd,nw_src=192.168.222.40,nw_dst=8.8.8.8,nw_tos=0,nw_ecn=0,nw_ttl=255,nw_frag=no,tp_src=0,tp_dst=22,tcp_flags=0

ingress(dp="int-net", inport="e4f83d")
--------------------------------------
 0. ls_in_check_port_sec (northd.c:8588): 1, priority 50, uuid 0b0cf77b
    reg0[15] = check_in_port_sec();
    next;
 4. ls_in_pre_acl (northd.c:5994): ip, priority 100, uuid 497a3dc7
    reg0[0] = 1;
    next;
 6. ls_in_pre_stateful (northd.c:6212): reg0[0] == 1, priority 100, uuid dad17c7d
    ct_next;

ct_next(ct_state=est|trk /* default (use --ct to customize) */)
---------------------------------------------------------------
 7. ls_in_acl_hint (northd.c:6300): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid 74203d1c
    reg0[8] = 1;
    reg0[10] = 1;
    next;
 8. ls_in_acl_eval (northd.c:6556): reg0[10] == 1 && (inport == @neutron_pg_drop && ip), priority 2001, uuid f82a272a
    reg8[17] = 1;
    ct_commit { ct_mark.blocked = 1; };
    next;
 9. ls_in_acl_action (northd.c:6734): reg8[17] == 1, priority 1000, uuid 95b30903
    reg8[16] = 0;
    reg8[17] = 0;
    reg8[18] = 0;
[root@osp-node-1 /]# 
```

Observăm că traficul se oprește in `ls_in_acl_action`, ceea ce indică faptul că nu trece de ACL. Implicit, ACL-urile au politică de `DROP`. În lipsa regulii `egress` care să permită accesul explicit spre exterior pentru orice protocol, orice trafic va fi blocat.

Linia relevantă este:

```bash
 9. ls_in_acl_action (northd.c:6734): reg8[17] == 1, priority 1000, uuid 95b30903
 ```

Mai exact: `uuid 95b30903`.

Verificăm ce face această regulă:

```bash
[root@osp-node-1 /]# ovn-sbctl lflow-list 95b30903
Datapath: "neutron-8e486692-3b40-4875-8243-052b5baf31a6" aka "int-net" (513f073e-b633-46ad-aeae-eebf69abf25f)  Pipeline: ingress
  table=9 (ls_in_acl_action   ), priority=1000 , match=(reg8[17] == 1), action=(reg8[16] = 0; reg8[17] = 0; reg8[18] = 0; /* drop */)
```

Observăm că este o regulă de tip `drop`.

Dacă însă adăugăm o nouă regula de egress care să permită accesul pe portul 22:

```bash
gabriel@arrakis:~$ openstack security group rule create --egress --dst-port 22 --protocol tcp --remote-ip 0.0.0.0/0 test-sg
+-------------------------+--------------------------------------+
| Field                   | Value                                |
+-------------------------+--------------------------------------+
| created_at              | 2024-05-22T12:17:33Z                 |
| description             |                                      |
| direction               | egress                               |
| ether_type              | IPv4                                 |
| id                      | ff8446cd-b461-4187-8357-2bf2745edaf5 |
| name                    | None                                 |
| port_range_max          | 22                                   |
| port_range_min          | 22                                   |
| project_id              | b8af9ef5cefd45989443e5d2caceab2c     |
| protocol                | tcp                                  |
| remote_address_group_id | None                                 |
| remote_group_id         | None                                 |
| remote_ip_prefix        | 0.0.0.0/0                            |
| revision_number         | 0                                    |
| security_group_id       | beb6f07a-ca99-4b62-abb6-d381da4930f4 |
| tags                    | []                                   |
| tenant_id               | b8af9ef5cefd45989443e5d2caceab2c     |
| updated_at              | 2024-05-22T12:17:33Z                 |
+-------------------------+--------------------------------------+
```

Apoi rulăm din nou `ovn-trace`:

```bash
[root@osp-node-1 /]# ovn-trace --ovs neutron-8e486692-3b40-4875-8243-052b5baf31a6 'inport=="e4f83d35-baad-41b3-af74-853dc6d308bd" &&
    eth.src==fa:16:3e:0a:76:09 &&
    ip4.src==192.168.222.40 &&
    eth.dst==fa:16:3e:36:fe:cd &&
    ip4.dst==8.8.8.8 &&
    tcp.dst==22 &&
    ip.ttl == 255'| grep -v cookie
# tcp,reg14=0x6,vlan_tci=0x0000,dl_src=fa:16:3e:0a:76:09,dl_dst=fa:16:3e:36:fe:cd,nw_src=192.168.222.40,nw_dst=8.8.8.8,nw_tos=0,nw_ecn=0,nw_ttl=255,nw_frag=no,tp_src=0,tp_dst=22,tcp_flags=0

ingress(dp="int-net", inport="e4f83d")
--------------------------------------
 0. ls_in_check_port_sec (northd.c:8588): 1, priority 50, uuid 0b0cf77b
    reg0[15] = check_in_port_sec();
    next;
 4. ls_in_pre_acl (northd.c:5994): ip, priority 100, uuid 497a3dc7
    reg0[0] = 1;
    next;
 6. ls_in_pre_stateful (northd.c:6212): reg0[0] == 1, priority 100, uuid dad17c7d
    ct_next;

ct_next(ct_state=est|trk /* default (use --ct to customize) */)
---------------------------------------------------------------
 7. ls_in_acl_hint (northd.c:6300): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid 74203d1c
    reg0[8] = 1;
    reg0[10] = 1;
    next;
 8. ls_in_acl_eval (northd.c:6518): reg0[8] == 1 && (inport == @pg_beb6f07a_ca99_4b62_abb6_d381da4930f4 && ip4 && ip4.dst == 0.0.0.0/0 && tcp && tcp.dst == 22), priority 2002, uuid 0f02753e
    reg8[16] = 1;
    next;
 9. ls_in_acl_action (northd.c:6730): reg8[16] == 1, priority 1000, uuid 024035a2
    reg8[16] = 0;
    reg8[17] = 0;
    reg8[18] = 0;
    next;
19. ls_in_acl_after_lb_action (northd.c:6756): 1, priority 0, uuid 96976122
    reg8[16] = 0;
    reg8[17] = 0;
    reg8[18] = 0;
    next;
27. ls_in_l2_lkup (northd.c:9414): eth.dst == fa:16:3e:36:fe:cd, priority 50, uuid f6a86a36
    outport = "05a052";
    output;

egress(dp="int-net", inport="e4f83d", outport="05a052")
-------------------------------------------------------
 0. ls_out_pre_acl (northd.c:5881): ip && outport == "05a052", priority 110, uuid e2f8fef2
    next;
 1. ls_out_pre_lb (northd.c:5881): ip && outport == "05a052", priority 110, uuid c6bf12fa
    next;
 3. ls_out_acl_hint (northd.c:6300): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid 23ca1ca8
    reg0[8] = 1;
    reg0[10] = 1;
    next;
 5. ls_out_acl_action (northd.c:6756): 1, priority 0, uuid 5727ef50
    reg8[16] = 0;
    reg8[17] = 0;
    reg8[18] = 0;
    next;
 9. ls_out_check_port_sec (northd.c:5846): 1, priority 0, uuid 8d6dc6b2
    reg0[15] = check_out_port_sec();
    next;
10. ls_out_apply_port_sec (northd.c:5851): 1, priority 0, uuid 74c5f950
    output;
    /* output to "05a052", type "patch" */

ingress(dp="router", inport="lrp-05a052")
-----------------------------------------
 0. lr_in_admission (northd.c:11779): eth.dst == fa:16:3e:36:fe:cd && inport == "lrp-05a052", priority 50, uuid 70ff7c1e
    xreg0[0..47] = fa:16:3e:36:fe:cd;
    next;
 1. lr_in_lookup_neighbor (northd.c:11963): 1, priority 0, uuid 3df83e10
    reg9[2] = 1;
    next;
 2. lr_in_learn_neighbor (northd.c:11972): reg9[2] == 1 || reg9[3] == 0, priority 100, uuid 2431ee5e
    next;
12. lr_in_ip_routing_pre (northd.c:12197): 1, priority 0, uuid d623d6b4
    reg7 = 0;
    next;
13. lr_in_ip_routing (northd.c:10602): reg7 == 0 && ip4.dst == 0.0.0.0/0, priority 1, uuid fc0bc09f
    ip.ttl--;
    reg8[0..15] = 0;
    reg0 = 10.8.21.1;
    reg1 = 10.8.21.214;
    eth.src = fa:16:3e:3e:b0:35;
    outport = "lrp-06bc20";
    flags.loopback = 1;
    next;
14. lr_in_ip_routing_ecmp (northd.c:12292): reg8[0..15] == 0, priority 150, uuid 98bc748d
    next;
15. lr_in_policy (northd.c:12457): 1, priority 0, uuid f98f0c44
    reg8[0..15] = 0;
    next;
16. lr_in_policy_ecmp (northd.c:12459): reg8[0..15] == 0, priority 150, uuid b7b2acc7
    next;
17. lr_in_arp_resolve (northd.c:12493): ip4, priority 1, uuid a2978ce1
    get_arp(outport, reg0);
    /* MAC binding to 00:e0:67:2c:cc:2e. */
    next;
20. lr_in_gw_redirect (northd.c:14748): ip4.src == 192.168.222.40 && outport == "lrp-06bc20" && is_chassis_resident("e4f83d"), priority 100, uuid 1d3f4912
    eth.src = fa:16:3e:c0:63:5e;
    reg1 = 10.8.21.212;
    next;
21. lr_in_arp_request (northd.c:13104): 1, priority 0, uuid 714b1003
    output;

egress(dp="router", inport="lrp-05a052", outport="lrp-06bc20")
--------------------------------------------------------------
 0. lr_out_chk_dnat_local (northd.c:14464): 1, priority 0, uuid ba6b8261
    reg9[4] = 0;
    next;
 1. lr_out_undnat (northd.c:13988): ip && ip4.src == 192.168.222.40 && outport == "lrp-06bc20", priority 100, uuid 246cdef7
    eth.src = fa:16:3e:c0:63:5e;
    ct_dnat;

ct_dnat /* assuming no un-dnat entry, so no change */
-----------------------------------------------------
 3. lr_out_snat (northd.c:14196): ip && ip4.src == 192.168.222.40 && outport == "lrp-06bc20" && is_chassis_resident("e4f83d") && (!ct.trk || !ct.rpl), priority 161, uuid 5880ef61
    eth.src = fa:16:3e:c0:63:5e;
    ct_snat(10.8.21.212);

ct_snat(ip4.src=10.8.21.212)
----------------------------
 6. lr_out_delivery (northd.c:13150): outport == "lrp-06bc20", priority 100, uuid be4b1621
    output;
    /* output to "lrp-06bc20", type "patch" */

ingress(dp="ext-net", inport="06bc20")
--------------------------------------
 0. ls_in_check_port_sec (northd.c:8588): 1, priority 50, uuid 0b0cf77b
    reg0[15] = check_in_port_sec();
    next;
 5. ls_in_pre_lb (northd.c:5878): ip && inport == "06bc20", priority 110, uuid c333d0db
    next;
27. ls_in_l2_lkup (northd.c:8530): 1, priority 0, uuid 74c652a7
    outport = get_fdb(eth.dst);
    next;
28. ls_in_l2_unknown (northd.c:8534): outport == "none", priority 50, uuid c1edd421
    outport = "_MC_unknown";
    output;

multicast(dp="ext-net", mcgroup="_MC_unknown")
----------------------------------------------

    egress(dp="ext-net", inport="06bc20", outport="provnet-c05c72")
    ---------------------------------------------------------------
         1. ls_out_pre_lb (northd.c:5881): ip && outport == "provnet-c05c72", priority 110, uuid 601ba5ad
            ct_clear;
            next;
         9. ls_out_check_port_sec (northd.c:5846): 1, priority 0, uuid 8d6dc6b2
            reg0[15] = check_out_port_sec();
            next;
        10. ls_out_apply_port_sec (northd.c:5851): 1, priority 0, uuid 74c5f950
            output;
            /* output to "provnet-c05c72", type "localnet" */
```

Observăm că de data aceasta, când este efectual `ls_in_acl_action`, UUID-ul este `024035a2`. Verificăm flow-ul relevant:


```bash
[root@osp-node-1 /]# ovn-sbctl lflow-list 024035a2
Datapath: "neutron-8e486692-3b40-4875-8243-052b5baf31a6" aka "int-net" (513f073e-b633-46ad-aeae-eebf69abf25f)  Pipeline: ingress
  table=9 (ls_in_acl_action   ), priority=1000 , match=(reg8[16] == 1), action=(reg8[16] = 0; reg8[17] = 0; reg8[18] = 0; next;)
```

Observăm că acțiunea este `next` ceea ce trimite pachetul mai departe spre procesare.