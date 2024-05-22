# Exemple de folosire a aplicației ovn-trace

În cele ce urmează vom prezenta un exemplu de folosire a aplicației `ovn-trace` pentru a urmări traficul ce trece printr-un SDN bazat pe OVN, într-un cloud de tip OpenStack. Scenariile ce le vom discuta sunt următoarele:

* **Cazul 1**: O mașină virtuală care trimite trafic către internet printr-un provider network, iar security group-urile sunt configurate corespunzător.
* **Cazul 2**: O mașină virtuală care trimite trafic către internet printr-un provider network, însă cu un security group care blochează traficul pe anumite porturi.



## Context

Aplicația `ovn-trace` se folosește de informațiile prezente in controllerul OVN pentru a simula traseul pe care un pachet îl parcurge în rețeaua SDN. Acest lucru este posibil deoarece toate informațiile pe baza cărora soluția de SDN ia decizii sunt stocate într-o bază de date centralizată, iar controllerele OVN crează reguli de tip OpenFlow ce sunt mai apoi propagate către switch-urile OVS.

Astfel, aplicația `ovn-trace` poate să aplice aceleași reguli pentru a determina cu exactitate traseul pe care un pachet îl va lua, în funcție de regulile ce sunt definite în rețeaua SDN, dar și în funcție de parametrii pe care noi îi furnizăm.

## Cazul 1

În cazul 1 vom simula un pachet ICMP de la un VM numit `jammy-test` conectat la o rețea numită `int_net`, către un IP de pe internet (`8.8.8.8`). Vom simula de asemenea și un pachet TCP de la același VM către același IP, pe portul 80.

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
+-----------+-----------------------+
| Field     | Value                 |
+-----------+-----------------------+
| addresses | int_net=192.168.20.75 |
+-----------+-----------------------+ 
```

Observăm că mașina virtuală `jammy-test` este conectată la rețeaua `int_net`, iar IP-ul său este `192.168.20.75`.

* Preluăm ID-ul rețelei `int_net`:

```bash
gabriel@arrakis:~$ openstack network show int_net -c id
+-------+--------------------------------------+
| Field | Value                                |
+-------+--------------------------------------+
| id    | 03862d6a-8df6-4a44-a8f0-a7fad6eff046 |
+-------+--------------------------------------+
```

* Preluăm ID-ul portului, adresa MAC a NIC-ului și adresa IP a mașinii virtuale:

```bash
gabriel@arrakis:~$ openstack port list --server jammy-test
+--------------------------------------+------+-------------------+------------------------------------------------------------------------------+--------+
| ID                                   | Name | MAC Address       | Fixed IP Addresses                                                           | Status |
+--------------------------------------+------+-------------------+------------------------------------------------------------------------------+--------+
| 5aac01db-6cc5-4a2a-bb61-2d7b00a31a0e |      | fa:16:3e:af:42:5f | ip_address='192.168.20.75', subnet_id='b413e4d7-1e6c-4926-ad3d-b2388039740d' | ACTIVE |
+--------------------------------------+------+-------------------+------------------------------------------------------------------------------+--------+
```

Observăm că ID-ul portului este `5aac01db-6cc5-4a2a-bb61-2d7b00a31a0e`, adresa MAC a NIC-ului este `fa:16:3e:af:42:5f`, iar adresa IP a mașinii virtuale este `192.168.20.75`. Observăm de asemenea că ID-ul subnetului este `b413e4d7-1e6c-4926-ad3d-b2388039740d`.

* Preluăm adresa MAC a default gateway-ului setat pe rețeaua la care este conectată mașina virtuală. Pentru aceasta, vom folosi ID-ul subnetului:

```bash
gabriel@arrakis:~$ openstack port list --fixed-ip subnet=b413e4d7-1e6c-4926-ad3d-b2388039740d --device-owner network:router_interface
+--------------------------------------+------+-------------------+-----------------------------------------------------------------------------+--------+
| ID                                   | Name | MAC Address       | Fixed IP Addresses                                                          | Status |
+--------------------------------------+------+-------------------+-----------------------------------------------------------------------------+--------+
| f020fa1b-c2e9-48d0-9572-8bca4691480b |      | fa:16:3e:fa:ba:67 | ip_address='192.168.20.1', subnet_id='b413e4d7-1e6c-4926-ad3d-b2388039740d' | ACTIVE |
+--------------------------------------+------+-------------------+-----------------------------------------------------------------------------+--------+
```

Observăm că adresa MAC a default gateway-ului este `fa:16:3e:fa:ba:67`.

Deci în cazul de față datele sunt:

* ID-ul rețelei `int_net`: `03862d6a-8df6-4a44-a8f0-a7fad6eff046`
* ID-ul portului: `5aac01db-6cc5-4a2a-bb61-2d7b00a31a0e`
* IP-ul mașinii virtuale: `192.168.20.75`
* MAC-ul mașinii virtuale: `fa:16:3e:af:42:5f`
* Adresa MAC a default gateway-ului: `fa:16:3e:fa:ba:67`
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
ovn-trace --ovs neutron-03862d6a-8df6-4a44-a8f0-a7fad6eff046 \
    'inport=="5aac01db-6cc5-4a2a-bb61-2d7b00a31a0e" &&
    eth.src==fa:16:3e:af:42:5f &&
    ip4.src==192.168.20.75 &&
    eth.dst==fa:16:3e:fa:ba:67 &&
    ip4.dst==8.8.8.8 &&
    icmp4.type==8 &&
    ip.ttl == 64'
```

Ceea ce va genera următorul output:

```bash
# icmp,reg14=0x3,vlan_tci=0x0000,dl_src=fa:16:3e:af:42:5f,dl_dst=fa:16:3e:fa:ba:67,nw_src=192.168.20.75,nw_dst=8.8.8.8,nw_tos=0,nw_ecn=0,nw_ttl=64,nw_frag=no,icmp_type=8,icmp_code=0

ingress(dp="int_net", inport="5aac01")
--------------------------------------
 0. ls_in_port_sec_l2 (northd.c:5652): inport == "5aac01", priority 50, uuid c5624a26
    next;
 3. ls_in_lookup_fdb (northd.c:5688): inport == "5aac01", priority 100, uuid 696906a0
    reg0[11] = lookup_fdb(inport, eth.src);
    /* MAC lookup for fa:16:3e:fa:ba:67 found in FDB. */
    next;
 5. ls_in_pre_acl (northd.c:5915): ip, priority 100, uuid b69e23d5
    reg0[0] = 1;
    next;
 7. ls_in_pre_stateful (northd.c:6095): reg0[0] == 1, priority 100, uuid 68fad8ff
    ct_next;

ct_next(ct_state=est|trk /* default (use --ct to customize) */)
---------------------------------------------------------------
 8. ls_in_acl_hint (northd.c:6183): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid 0eef6945
    reg0[8] = 1;
    reg0[10] = 1;
    next;
 9. ls_in_acl (northd.c:6425): reg0[8] == 1 && (inport == @pg_0eb76931_dc33_45a1_9698_8e2ad10a0aeb && ip4), priority 2002, uuid ce2f348c
    next;
24. ls_in_l2_lkup (northd.c:8697): eth.dst == fa:16:3e:fa:ba:67, priority 50, uuid ca2f6731
    outport = "f020fa";
    output;

egress(dp="int_net", inport="5aac01", outport="f020fa")
-------------------------------------------------------
 0. ls_out_pre_acl (northd.c:5802): ip && outport == "f020fa", priority 110, uuid 1a94f5b6
    next;
 1. ls_out_pre_lb (northd.c:5802): ip && outport == "f020fa", priority 110, uuid 8cd292c8
    next;
 3. ls_out_acl_hint (northd.c:6183): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid d690351b
    reg0[8] = 1;
    reg0[10] = 1;
    next;
 9. ls_out_port_sec_l2 (northd.c:5749): outport == "f020fa", priority 50, uuid 10e4b56d
    output;
    /* output to "f020fa", type "patch" */

ingress(dp="router1", inport="lrp-f020fa")
------------------------------------------
 0. lr_in_admission (northd.c:10984): eth.dst == fa:16:3e:fa:ba:67 && inport == "lrp-f020fa", priority 50, uuid 3280dc2e
    xreg0[0..47] = fa:16:3e:fa:ba:67;
    next;
 1. lr_in_lookup_neighbor (northd.c:11147): 1, priority 0, uuid b6169135
    reg9[2] = 1;
    next;
 2. lr_in_learn_neighbor (northd.c:11156): reg9[2] == 1 || reg9[3] == 0, priority 100, uuid c5899ec8
    next;
10. lr_in_ip_routing_pre (northd.c:11382): 1, priority 0, uuid f227e1df
    reg7 = 0;
    next;
11. lr_in_ip_routing (northd.c:9861): reg7 == 0 && ip4.dst == 0.0.0.0/0, priority 1, uuid 39891982
    ip.ttl--;
    reg8[0..15] = 0;
    reg0 = 10.0.9.1;
    reg1 = 10.0.9.243;
    eth.src = fa:16:3e:f6:2b:f7;
    outport = "lrp-279a07";
    flags.loopback = 1;
    next;
12. lr_in_ip_routing_ecmp (northd.c:11458): reg8[0..15] == 0, priority 150, uuid bc3a8d4c
    next;
13. lr_in_policy (northd.c:11592): 1, priority 0, uuid 5e60658a
    reg8[0..15] = 0;
    next;
14. lr_in_policy_ecmp (northd.c:11594): reg8[0..15] == 0, priority 150, uuid dc4905e1
    next;
15. lr_in_arp_resolve (northd.c:11628): ip4, priority 0, uuid eda364aa
    get_arp(outport, reg0);
    /* MAC binding to 00:16:3e:8d:bb:1f. */
    next;
18. lr_in_gw_redirect (northd.c:12195): outport == "lrp-279a07", priority 50, uuid e64620ff
    outport = "cr-lrp-279a07";
    next;
19. lr_in_arp_request (northd.c:12312): 1, priority 0, uuid e562d972
    output;
    /* Replacing type "chassisredirect" outport "cr-lrp-279a07" with distributed port "lrp-279a07". */

egress(dp="router1", inport="lrp-f020fa", outport="lrp-279a07")
---------------------------------------------------------------
 0. lr_out_chk_dnat_local (northd.c:13552): 1, priority 0, uuid 75fc2a85
    reg9[4] = 0;
    next;
 3. lr_out_snat (northd.c:13303): ip && ip4.src == 192.168.20.0/24 && outport == "lrp-279a07" && is_chassis_resident("cr-lrp-279a07"), priority 153, uuid 290bbb36
    ct_snat_in_czone(10.0.9.243);

ct_snatin_czone(ip4.src=10.0.9.243)
-----------------------------------
 6. lr_out_delivery (northd.c:12359): outport == "lrp-279a07", priority 100, uuid 35258556
    output;
    /* output to "lrp-279a07", type "patch" */

ingress(dp="ext_net", inport="279a07")
--------------------------------------
 0. ls_in_port_sec_l2 (northd.c:5652): inport == "279a07", priority 50, uuid f5d667ea
    next;
 6. ls_in_pre_lb (northd.c:5799): ip && inport == "279a07", priority 110, uuid f818eae1
    next;
24. ls_in_l2_lkup (northd.c:7895): 1, priority 0, uuid 511746fb
    outport = get_fdb(eth.dst);
    next;
25. ls_in_l2_unknown (northd.c:7899): outport == "none", priority 50, uuid 251ec38e
    outport = "_MC_unknown";
    output;

multicast(dp="ext_net", mcgroup="_MC_unknown")
----------------------------------------------

    egress(dp="ext_net", inport="279a07", outport="provnet-785e63")
    ---------------------------------------------------------------
         1. ls_out_pre_lb (northd.c:5802): ip && outport == "provnet-785e63", priority 110, uuid 25689a7c
            next;
         9. ls_out_port_sec_l2 (northd.c:5749): outport == "provnet-785e63", priority 50, uuid 4cc71034
            output;
            /* output to "provnet-785e63", type "localnet" */
```

Putem să observăm traseul pachetului prin infrastructura virtuală, începând de la portul de intrare al rețelei `int_net` (`5aac01`) atașat la VM, trecând prin routerul `router1` via `f020fa` (portul asociat default GW preluat mai sus) unde se produce translatarea NAT (`279a07`) și ajungând la portul de ieșire al rețelei `ext_net` (`provnet-785e63`).

Cu excepția `provnet-785e63`, care corespunde cu portul fizic efectiv, celelalte ID-uri abreviate corespund cu porturi logice ce se regăsesc și in Neutron:

* `5aac01` (`5aac01db-6cc5-4a2a-bb61-2d7b00a31a0e`) - este portul VM-ului preluat la inceputul exemplului
* `f020fa` (`f020fa1b-c2e9-48d0-9572-8bca4691480b`) - este portul default GW preluat la inceputul exemplului
* `lrp-279a07` - este portul de ieșire al routerului `router1` unde se face translatarea NAT. `lrp` vine de la `logical router port`. ID-ul poate fi găsit folosind comanda:

```bash
gabriel@arrakis:~$ openstack port list --long| grep 279a07
| 279a0766-2c29-42e1-bcc1-e5a1f6ac749a |      | fa:16:3e:f6:2b:f7 | ip_address='10.0.9.243', subnet_id='7e6fa7ff-0e56-4170-8f10-c3245be0ba87'    | ACTIVE | None            | network:router_gateway   |      |
```

Observăm că portul este de tip `network:router_gateway`, deci este un port de ieșire al unui router, iar adresa IP asociată este IP-ul public al routerului. În lipsa unui floating IP asociat VM-ului, aceasta va fi adresa prin care pachetul va ieși pe internet.

Este important de reținut acest aspect pentru ultimul pas.

Dacă `ovn-trace` ne indică faptul că pachetul ar trebui să ajungă pe fir (cum observăm mai sus), însă acest lucru nu se întâmplă, atunci trebuie să verificăm dacă într-adevăr pachetul este sau nu pus pe fir. Cu informațiile de mai sus, putem să determinăm punctul de ieșire din SDN și să verificăm dacă pachetul ajunge acolo.

În output-ul de mai sus, observăm la final că pachetul intră pe chassis gateway prin portul `279a07` și este trimis către portul `provnet-785e63`:

```bash
egress(dp="ext_net", inport="279a07", outport="provnet-785e63")
```

Pentru a putea să inspectăm traficul pe fir când iese din SDN, trebuie să accesăm nodul fizic și să folosim `tcpdump` sau `wireshark` pentru a inspecta pachetele. Dar înainte de asta, trebuie să determinăm nodul fizic pe care se află portul `279a07`:

```bash
root@juju-bd2abe-0-lxd-3:~# ovn-sbctl --format=json list Port_Binding 279a07  | jq '.data[0][4][1] | map(select(.[0] == "neutron:host_id")) | .[0][1]'
"juju-bd2abe-4"
```

Putem de asemenea să rulăm:

```bash
root@juju-bd2abe-0-lxd-3:~# ovn-sbctl show
Chassis juju-bd2abe-4
    hostname: juju-bd2abe-4
    Encap geneve
        ip: "10.0.9.21"
        options: {csum="true"}
    Port_Binding cr-lrp-279a0766-2c29-42e1-bcc1-e5a1f6ac749a
    Port_Binding "5aac01db-6cc5-4a2a-bb61-2d7b00a31a0e"
```

și să căutăm după `279a07` pentru a vedea pe ce nod fizic se află portul. Prima variantă ne permite să extragem direct informația dorită.

Accesăm nodul fizic `juju-bd2abe-4` și rulăm `tcpdump` pentru a inspecta pachetele. Pe nodul fizic, verificăm portul folosit in bridge-ul extern ce corespunde `provnet-785e63`:

```bash
root@juju-bd2abe-4:~# ovs-vsctl show
838bb9bc-9e6a-4823-ae8c-5baa41ebab28
    Manager "ptcp:6640:127.0.0.1"
        is_connected: true
    Bridge br-ex
        fail_mode: standalone
        datapath_type: system
        Port eth1
            Interface eth1
                type: system
        Port br-ex
            Interface br-ex
                type: internal
        Port patch-provnet-785e6353-8a81-46f3-94cd-1b3113f3bfd0-to-br-int
            Interface patch-provnet-785e6353-8a81-46f3-94cd-1b3113f3bfd0-to-br-int
                type: patch
                options: {peer=patch-br-int-to-provnet-785e6353-8a81-46f3-94cd-1b3113f3bfd0}
    Bridge br-int
        fail_mode: secure
        datapath_type: system
        Port br-int
            Interface br-int
                type: internal
        Port patch-br-int-to-provnet-785e6353-8a81-46f3-94cd-1b3113f3bfd0
            Interface patch-br-int-to-provnet-785e6353-8a81-46f3-94cd-1b3113f3bfd0
                type: patch
                options: {peer=patch-provnet-785e6353-8a81-46f3-94cd-1b3113f3bfd0-to-br-int}
        Port tap03862d6a-80
            Interface tap03862d6a-80
        Port tap5aac01db-6c
            Interface tap5aac01db-6c
    ovs_version: "2.17.9"
```

Observăm că in `br-ex` avem portul fizic `eth1`.

Știm că trimitem pachete ICMP către `8.8.8.8`. Știm de asemenea că pentru a ajunge pe internet, se face NAT de la IP-ul privat al VM-ului către IP-ul "public" `10.0.9.243`.

Rulăm tcpdump:

```bash
root@juju-bd2abe-4:~# tcpdump -nei eth1 icmp and host 10.0.9.243
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

Accesăm VM-ul și rulăm `ping`. E important de ținut minte că `ovn-trace` nu generează trafic efectiv. Doar simuleaza trafic bazat pe regulile openflow prezente in OVN.

Dacă totul functionează corect, vom vedea pachetele ICMP trimise de VM către destinație, precum și răspunsurile de la destinație.

Dacă nu vedem pachete că pleacă din SDN, există posibilitatea să existe o problema la nivel fizic a rețelei ce asigură traficul între nodurile ce participă la SDN.

Dacă vedem că pleacă pe fir pachetele ICMP, însă nu vin răpunsuri, atunci problema este probabil una de rutare, după ce pachetul iese din SDN, iar soluția espe probabil pe gateway-ul upstream.

Pentru a testa conectivitatea către portul 80, comanda `ovn-trace` va fi similară cu cea de mai sus, cu excepția faptului că vom schimba portul ICMP cu portul 80:

```bash
ovn-trace --ovs neutron-03862d6a-8df6-4a44-a8f0-a7fad6eff046 \ 
    'inport=="5aac01db-6cc5-4a2a-bb61-2d7b00a31a0e" &&
    eth.src==fa:16:3e:af:42:5f &&
    ip4.src==192.168.20.75 &&
    eth.dst==fa:16:3e:fa:ba:67 &&
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
| project_id      | a9212c0a022944329aaa1d69ce87c286 |
| security_groups | name='default'                   |
+-----------------+----------------------------------+
```

Preluăm ID-ul security group-ului `default`:

```bash
gabriel@arrakis:~$ openstack security group list --project a9212c0a022944329aaa1d69ce87c286 -c Name -c ID --format=json | jq 'select(.[].Name == "default")[0].ID'
"0eb76931-dc33-45a1-9698-8e2ad10a0aeb"
```

Verificăm regulile setate pe security group-ul `default`:

```bash
gabriel@arrakis:~$ openstack security group rule list --egress 0eb76931-dc33-45a1-9698-8e2ad10a0aeb
+--------------------------------------+-------------+-----------+-----------+------------+-----------+-----------------------+----------------------+
| ID                                   | IP Protocol | Ethertype | IP Range  | Port Range | Direction | Remote Security Group | Remote Address Group |
+--------------------------------------+-------------+-----------+-----------+------------+-----------+-----------------------+----------------------+
| 33148d73-15c3-43d3-a569-64af1de95d8c | None        | IPv6      | ::/0      |            | egress    | None                  | None                 |
| d6bfca5c-fe95-4d1c-b7e5-cea2fd67387e | None        | IPv4      | 0.0.0.0/0 |            | egress    | None                  | None                 |
+--------------------------------------+-------------+-----------+-----------+------------+-----------+-----------------------+----------------------+
```

Ștergem regula egress implicită ce permite traficul pe orice port:

```bash
gabriel@arrakis:~$ openstack security group rule delete d6bfca5c-fe95-4d1c-b7e5-cea2fd67387e
```

Fără această regulă, nici un fel de trafic nu va mai fi permis pe ipv4 spre exterior. Rulăm din nou comanda `ovn-trace` pentru a vedea ce se întâmplă:

```bash

```