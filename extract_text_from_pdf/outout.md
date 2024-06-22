# Page 1

1VPN, MPLS, L2TP, IPsec 


Virtuelne privatne mreže - VPN 
• Virtuelna privatna mreža je mreža jedne institucije ili 
grupe korisnika realizovana preko javne ili deljene 
infrastrukture (Internet, provajderske mreže) 
• VPN tehnologije: 
– Frame Relay 
– ATM 
– IP VPN tehnologije: 
• MPLS 
• IPsec 
• SSL 
• L2TP 
• GRE 
• Q-in-Q
• …


# Page 2

Razlozi za uvo đenje VPN 
• Potreba za novim aplikacijama 
– e-commerce, e-business 
– Bandwidth on demand 
– Voice/Video over IP 
– mobilnost 
• Sigurnosni problemi 
• Bolja organizacija saobra ćaja, rutiranja 
• Nedostatak podrške za QoS 
• Problem broja IP adresa i migracija na IPv6 

Vrste VPN ure đaja 
• Podela prema tome 
kome pripadaju 
uređaji i gde su u 
VPN: 
– C – customer 
– CE – customer edge 
– PE – provider edge 
– P – provider PE 
![alt text](image.png)

# Page 3

Podele VPN 
• Po tome ko ih realizuje: 
– Provider provisioned 
– Customer enabled 
• Po vrsti servisa: 
– Site-to-site (LAN-to-LAN) 
• Intranet (lokacije jedne institucije) 
• Extranet (povezivanje razli čitih institucija) 
– Remote Access 
• Compulsory (access server inicira VPN vezu) 
• Voluntary (klijent inicira VPN vezu) 
• Po sloju rada: L1, L2, L3 
• Po poverljivosti podataka 
– Trusted VPN 
– Secure VPN 

6MPLS tehnologija 
• Klasičan IP ne može da pruži neke servise koji 
su vremenom postali zna čajni za ozbiljne 
primene u oblasti pružanja telekomunikacionih 
servisa (QoS, traffic engineering, VPN,...) 
• ATM je zamišljen kao tehnologija koja bi 
rešavala navedene probleme, ali ATM nije 
uspeo da se nametne kao dominantna 
tehnologija 
• 1996. formirana MPLS grupa u okviru IETF. Prvi 
RFC 1999 

# Page 4

IP problem – saobraćaj se rutira po putanjama najmanjeg cost-a
![alt text](image-1.png)

Problem odnosa L2 i L3 tehnologija 
• L2 tehnologije (FR, ATM) 
mogu da pruže neke od 
zahtevanih servisa 
• L2 tehnologije ne mogu da 
vrše prosle đivanje na 
osnovu IP adresa 
• Neoptimalno rutiranje 
• Stati čko postavljanje L2 
logičkih veza 
• Neskalabilnost 
• Teška procena potrebnog 
propusnog opsega FR,ATM 

![alt text](image-2.png)

# Page 5

Problem – IP rutiranje je relativno sporo 
• Klasično IP rutiranje – svaki paket se 
nezavisno procesira i za svaki paket se 
donosi nezavisna odluka 
• Mogu će je da se izbegne rutiranje na 
osnovu destinacije – Policy based routing, 
ali ono je sporo i procesorski zahtevno 
• Tako đe, IP zaglavlje ima više informacija 
nego što je potrebno za prosle đivanje 
paketa, pa je njegovo procesiranje sporije 

Procesiranje paketa 
• Kada paket dodje u ruter obavljaju se 
sledece aktivnosti: 
– Proverava se L2 checksum 
– Proverava se IP header Checksum 
• Kada se paket prosledjuje: 
– Menjaju se source i dest MAC adrese 
– Dekrementira se TTL 
– Racuna se novi IP header Checksum 
– Racuna se novi L2 checksum 


# Page 6

Vrste prosle đivanja paketa 
• Process/interrupt switching 
– Prosle đivanje u softveru 
– Svaki paket se nezavisno prosle đuje 
• Fast switching (cache) 
– Prvi paket namenjen nekoj destinaciji se prosle đuje 
po process switching metodi, pravi se ulaz u 
switching kešu 
– Svi čing keš sadrži IP adresu destinacije, next hop, L2 
rewrite info 
– Ostali paketi iz istog toka se prosle đuju brže, na 
osnovu zapisa u switching kešu 
• Hardversko prosle đivanje 
– Razdvojen control plane i data plane 
– Forwarding tabela se puni na osnovu routing tabele 

Cisco express forwarding (CEF) 
• FIB (Forwarding Information Base) tabela i Adjacen cy tabela (na 
posebnim ASIC čipovima) 
• FIB se puni iz ruting tabele 
• Adjacency tabela – L2 informacije koje je potrebno upisati u odlazni 
paket 
• Postoji centralizovani CEF (FIB i Adjacency tabele  na centralnom Route 
procesoru) i distribuirani (FIB i Adjacency tabele na svakoj interfejs 
kartici) 

# Page 7

Juniper arhitektura 
(M5, M10, M40, M160) 
![alt text](image-3.png)


Juniper PFE 
• Razlicite platforme imaju razli čite arhitekture: 
– Forwarding Engine Board (FEB) (M5/M10 ruteri), 
– System and Switch Board (SSB) (M20 ruteri), 
– Switching and Forwarding Module (SFM) (M40e i M160  ruteri) 
• Zasnovane na ASIC čipovima 
• M40e/M160 SFM (usmerava, filtrira i prosle đuje do 40Mpps):
– Forwarding tabela u sinhronom SRAM (Internet Proces sor II ASIC ) 
– Upravljanje deljenom memorijom (baferima) za FPC (k oncentratori 
kartica sa interfejsima) radi se na Distributed buf fer management 
ASIC (DBM) – dolazni paketi se smestaju u bafere 
– Drugi DBM prosle đuje pakete do izlaznog FPC gde se paket sprema 
za slanje 
– Internet Processor II ASIC šalje informacije o gre škama i kontrolne 
pakete procesoru na SFM, koji ih prosle đuje Route engine-u 

# Page 8

MPLS (RFC 3031) 
• MPLS – mehanizam za brzo prosle đivanje 
paketa, ne nužno na osnovu destanacione 
adrese, sa mogu ćnoš ću pružanja razli čitih 
servisa 
• Ideja: saobra ćaj razvrstati u FEC klase i za 
svaku FEC klasu odrediti NextHop 
• FEC – Forwarding Equvalence Class 
• Paketi se ozna čavaju prema FEC klasi na 
ulasku u mrežu (PE ure đaj) 
• Oznaka se zove labela 

MPLS (RFC 3031) 
• Nakon ulaska u mrežu paketi se na P ure đajima 
prosle đuju na osnovu labele 
• Svi PE i P ure đaji poseduju tabele parova 
(labela, next_hop) i prosle đuju pakete ka MPLS 
mreži na osnovu labela 
• Labele nisu jedinstvene za neku FEC u celoj 
mreži, ve ć se na svakom ure đaju menjaju 
• Razlike u odnosu na WAN tehnologije 
– Labele se dodeljuju na osnovu IP adresa 
– Može da postoji niz labela 

# Page 9

Put paketa kroz MPLS mrežu 
![alt text](image-4.png)

MPLS prosleđivanje 
• Labele se naj češ će dodeljuju na osnovu destinacione IP 
adrese paketa, ali nisu kodovane u labelu. 
• Labele mogu da se dodeljuju i na osnovu drugih 
parametara, poput interfejsa preko kog je stigao paket, 
na osnovu rutera,... 
• Na taj na čin se menja osnovna paradigma IP rutiranja 
koje je isklju čivo zasnovano na destinacionoj adresi 
• U MPLS razli čite putanje ka istoj destinaciji mogu da 
imaju paketi koji su u mrežu ušli preko npr. razli čitih 
rutera ili razli čitih interfejsa jednog rutera 
• MPLS source routing – predefinisana putanja za neku 
FEC 

# Page 10

Format labele (RFC 3032) 

![alt text](image-5.png)

• Exp – Experimental – za organizaciju redova za čekanje 
• S – Bottom of Stack bit – 0 ako iza date labele postoji još 
jedna labela, 1 ako nema više labela 
• Labele od 0 do 15 su rezervisane 
• U Labeli ne postoji polje za protokol 3. sloja enkapsuliran 
labelom, pa ruteri implicitno prilikom dodeljivanja labela 
moraju da vode računa o tome da je za odre đene labele  
enkapsuliran odre đeni protokol 3. sloja 


Zašto Multiprotocol? 
• Labela se smešta između protokola 2. i 3. 
sloja 
![alt text](image-6.png)

# Page 11

MPLS terminologija 
• LSR – Label Switching 
Router 
• Ru – Upstream ruter 
• Rd – Downstream ruter 
• Labela L je outgoing za Ru, 
a incoming za Rd 
• Ru i Rd moraju da se slože 
da odre đena L odgovara 
nekoj FEC kako bi znali 
na čin na koji će da izvrše 
label switching 
![alt text](image-7.png)

Dodeljivanje labela 
• Labelu nekoj FEC dodeljuje ruter bliži destinaciji  
(downstream) 
• Labele nakon toga propagiraju ka upstream 
ruterima 
• Labele su “downstream asigned” 
• Labele mogu da imaju pridružene i atribute 
• Ruteri informišu jedan drugog o na činu 
povezivanja FEC i labele putem razli čitih 
protokola: 
– LDP 
– MPBGP 
– RSVP 

# Page 12

Label Distribution Protocol – LDP (RFC 3036) 
• LDP koristi TCP protokol po portu 646 
• Uspostavljaju se susedski odnosi putem Hello 
paketa 
• Vrši se razmena labela i prefiksa 
• Režimi rada LDP: 
– Unsolicited vs. On demand 
– Independent vs. Ordered control 
– Liberal retention vs. Conservative retention 
• Dozvoljene su razli čite kombinacije režima rada 

Unsolicited vs. On demand 
–Unsolicited – ruter šalje svoje parove (FEC 
(prefiks),labela) svim susednim ruterima, bez 
pitanja. Ruter poredi next hop rute u svojoj 
ruting tabeli sa ruterom od kog je dobio par. 
Ukoliko je par dobijen od next hop rutera za 
dati prefiks (a to je downstream ruter), labela 
se prihvata 
–On demand – ruter šalje svoje parove (FEC 
(prefiks),labela) po zahtevu susednog rutera 

# Page 13

Independent vs. Ordered control 
–Independent control - ruter dodeljuje labele 
prefiksima u svojoj ruting tabeli i šalje ih bez 
obzira na to da li je ruter dobio mapiranje u 
labelu za  za tu rutu od downstream rutera 
–Ordered control – Ruter šalje svoje 
(FEC,labela) parove samo za one FEC za 
koje ima mapiranje dobijeno od downstream 
rutera 

Liberal retention vs. Conservative 
retention 
•Liberal retention – ruter čuva sve parove (FEC, 
Labela) dobijene od svih suseda, a prosle đuje 
pakete na osnovu labela dobijenih od nizvodnog 
rutera 
•Conservative retention - ruter čuva samo one 
parove (FEC, Labela) dobijene od downstream 
suseda za dati FEC (od Next Hop) 
•Liberal – više memorije, brza konvergencija 
•Conservative – manje memorije, sporija 
konvergencija 

# Page 14

Frame-mode MPLS 
• Režim kada se MPLS koristi kao zamena 
za klasi čno destination based rutiranje 
• MPLS se čvrsto oslanja na IP rutiranje i 
interni protokol rutiranja i labele se 
dodeljuju na osnovu ruta u riting tabeli 
• LDP mehanizam rada je naj češ će: 
independent control with unsolicited 
downstream and liberal retention 


Propagacija labela 

![alt text](image-8.png)
• Na slici je nacrtana samo aktivna topologija 
• U stvarnosti, labele propagiraju ka svim 
susednim ruterima 


# Page 15

Tabele u MPLS uređajima 

![alt text](image-9.png)

Arhitektura MPLS LSR rutera 

![alt text](image-10.png)

# Page 16

Arhitektura MPLS Edge LSR rutera 

![alt text](image-11.png)


# Page 17
![alt text](image-12.png)
![alt text](image-13.png)

# Page 18

![alt text](image-14.png)

![alt text](image-15.png)

# Page 19

![alt text](image-16.png)
![alt text](image-17.png)

# Page 20

Petlje u MPLS mreži 
•Unsolicited downstream metod narušava split 
horizon pravilo. 
• MPLS Frame mode se oslanja na protokole 
rutiranja koji obezbe đuju da nema petlji 
• LDP poseduje mehanizam zaštite od petlji koji 
može da se uklju či u zavisnosti od režima rada 
LDP 
• Detekcija petlji se vrši po principu sli čnom onom 
u BGP – uz parove (labela,prefiks) u LDP 
porukama mogu da se šalju Path vector atributi 
u kojima je lista svih rutera koji su oglasili dati  
par 

Konvergencija MPLS mreže 
• Promena ruting tabele povla či promenu u 
labelama (nove labele ili labele koje 
nestaju) 
• Vreme konvergencije = vreme 
konvergencije IGP + vreme konvergencije 
LDP 
•independent control with unsolicited 
downstream with liberal retention režim 
rada je izabran jer pruža najbržu 
konvergenciju 

# Page 21

LDP i BGP 
•Sve rute dobijene BGP protokolom 
imaju istu labelu kao njihov Next hop!!! 
• BGP prefiksi nemaju svoje labele! 
• P ruteri ne moraju da razmenjuju BGP 
rute, ve ć je dovoljno da imaju rutu (labelu) 
ka Next Hop mreži 

LDP i BGP
![alt text](image-18.png)
• Nije potreban potpun IBGP graf 
• P ruteri ne moraju uopšte da pokre ću BGP 
proces 
• U slu čaju punih Internet ruting tabela – značajna 
ušteda resursa 

# Page 22

Traceroute kod MPLS 
• Da bi funkcionisao traceroute mehanizam, 
ruteri na kome se paketi odbacuju moraju 
da u ruting tabeli imaju rutu kao source 
adresi 
• Šta ako paket treba da odbaci P ruter koji 
nema punu ruting tabelu? 
• TTL iz IP paketa mora da se preslika u 
TTL u labeli 

MPLS traceroute 
![alt text](image-19.png)

# Page 23

PHP 
• Poslednji ( egress ) ruter MPLS mreže treba da 
uradi slede će: 
– da primi paket sa odre đenom labelom, 
– da proveri u tabeli labela šta sa tim paketom 
– da skine labelu i da ga prosledi van mreže klasi čnim 
IP rutiranjem (da pogleda IP ruting tabelu) 
• Dvostruko gledanje u tabele – neoptimalno 
• Zato je dobro da se labela skida na 
pretposlednjem ruteru ( Penultimate Hop 
Popping ), pa da se paket od pretposlednjeg do 
poslednjeg rutera prosledi klasi čnim IP 
• Poslednji ruter pretposlednjem šalje “implicit 
null” labelu 


L3 VPN modeli 
• Overlay 
– Provajder kreira virtuelna iznajmljena kola 
korisniku 
– Jasno razdvajanje PE i CE 
• Peer to peer 
– PE i CE razmenjuju informacije o rutama 

# Page 24

Prednosti Peer to peer modela 
• Jednostavnije rutiranje (iz perspektive 
korisnika) – samo razmena ruta CE-PE 
• Optimalno rutiranje izme đu CE ure đaja 
• Jednostavnije pružanje garantovanih 
propusnih opsega 
• Jednostavnije dodavanje nove lokacije –
skalabilnost 
48 MPLS/VPN 
• Kreiranje privatnih mreža preko MPLS 
infrastrukture 
• Zahtevi: 
– Svaka privatna mreža može da ima 
proizvoljan skup adresa 
– Svaka privatna mreža može da ima nezavisno 
interno rutiranje (slanje informacija o rutama 
unutar jedne od lokacija) 

# Page 25

VRF - VPN Routing and 
Forwarding instance 

![alt text](image-20.png)

• VRF čuva adrese i rute iz date 
VPN i razmenjuje ih sa drugim 
VRF instancama date VPN 
• Omogu ćavaju rad sa proizvoljnim 
adresnim prostorima 
• Postoje na PE ruterima 
• Na jednom PE ruteru može da 
postoji više VRF 
• Interfejs PE rutera može da 
pripada samo jednoj VRF, 
odnosno, interfejs se dodeljuje 
odre đenoj VRF 
• Jedna VPN može da ima jednu ili 
više VRF na jednom PE ruteru 
• Da li VRF mogu da koriste 
nezavisne protokole rutiranja? MPLS VPN1

![alt text](image-21.png)

Route distinguisher 
• PE ruteri razmenjuju korisni čke rute obeležene “route 
distingusher”-om 
• Svakom interfejsu koji je u nekoj VRF instanci se 
dodeljuje jedan RD 
• Route distingusher je oznaka kojom se obeležavaju rute 
koje pripadaju pojedinoj VRF instanci ≈ VPN identifikator 
(jedna VPN može da ima i više RD) 
• RD je 64-bitna vrednost; naj češ ći na čin ozna čavanja  
ASN provajdera: broj 
• RD + IP prefiks = VPN prefiks 
• Korisni čke rute se razmenjuju izme đu PE rutera putem 
MP-BGP – najskalabilnije rešenje 

# Page 26

Propagacija ruta kroz MPLS VPN 

![alt text](image-22.png)

Prosle đivanje paketa 
• Da bi se razlikovao saobra ćaj izme đu 
razli čitih VPN, paketi moraju da budu na 
neki na čin obeleženi 
• Obeležavanje se vrši drugim setom labela, 
koje su enkapsulirane u labele za prenos 
paketa po MPLS mreži 

# Page 27

![alt text](image-23.png)
Prosle đivanje paketa – detaljno 


![alt text](image-24.png)

# Page 28

Prosle đivanje paketa – detaljno 
![alt text](image-25.png)

![alt text](image-26.png)

# Page 29

MPLS VPN primer 
![alt text](image-27.png)

Konfiguracija klijentskih rutera
R9 - VPNB

![alt text](image-28.png)

# Page 30

Ruting tabela klijentskih rutera -
VPNB 

![alt text](image-29.png)

# Page 31

![alt text](image-30.png)



# Page 35

3569 MPLS TE – RFC 2702 
• Traffic Engineering – skup metoda kojima 
se optimalno iskoriš ćavaju resursi mreže 
• Osnovna ideja: omogu ćiti da se 
prosle đivanje paketa vrši na osnovu 
– topologije mreže, 
– skupa ograni čenja 
– raspoloživih resursa 
• MPLS TE – niz mehanizama kojima se 
automatizuje kreiranje TE LSP 
70 Atributi (ograni čenja) na osnovu 
kojih se odre đuje optimalni LSP 
• Destinacija 
• Propusni opseg 
• Afinitet (svaki link po 32 “boje”, po 
kašnjenju, nekoj karakteristici linka...)
• Pre če pravo (Preemption) 
• Optimizovana metrika 
• Zaštita pomo ću Fast Reroute mehanizma 

# Page 36

3671 Pre če pravo (preemption) 
• LSP ve ćeg prioriteta u slu čaju nedovoljnih 
resursa ima pravo da raskine LSP nižeg 
prioriteta 
• Primer: 
– Ukupni propusni opseg potreban za LSP T1, 
T2,T3, T4 je ve ći od raspoloživog 
– T1 ima ve ći prioritet od T2, T3, T4 
– LSP sa najnižim prioritetom će biti raskinut 
72 Šta ako ni jedan TE-LSP ne 
zadovoljava postavljene uslove? 
• Može da se kreira Fallback sekvenca 
razli čitih uslova za dati TE LSP 
• Poslednji tip TE LSP u ovoj sekvenci može 
da bude kreiranje putanje po IGP putanji 
• Prilikom reoptimizacije headend ruter će 
ponovo pokušati da uspostavi TE LSP 
po čev od prvog skupa uslova. 

# Page 37

3773 Optimizovana metrika 
• “druga” metrika – RFC 3785 
• Jedna metrika – klasi čna IGP metrika 
• Druga metrika – metrika za CBR 
• Za jedan LSP se putanja odre đuje na 
osnovu jedne od ove dve metrike 
• Pronalaženje optimalne putanje po obe 
metrike istovremeno je NP-potpun 
problem 
74 Odre đivanje TE LSP 
• Offline 
– LSP se izra čunava van rutera i implementira 
na njima 
– Optimalne putanje 
• Online 
– Sami ruteri izra čunavaju najbolje LSP (CSPF) 
– Neoptimalne putanje 
– Otporno na promene u mreži 
– Skalabilnije 

# Page 38

3875 CSPF, CBR 
• CBR – Constrained Based Routing 
• CSPF - Constrained Shortest Path First 
• Ne postoji definisan standard 
• Postoje ekstenzije za OSPF i ISIS 
• Princip: 
– Dijkstra algoritam se primenjuje na osnovni graf iz kog  su 
izba čene grane koje ne zadovoljavaju neki kriterijum 
– Izme đu ostalih grana se bira ona sa najmanjim cost-om 
– Ako postoji više putanja bira se ona sa najve ćim 
minimalnim propusnim opsegom 
– Ako to ne razreši, bira se ona sa najmanjim brojem hop ova 
– Ako to ne razreši, bira se nasumi čno 
76 CSPF 
50 
100 100 
100 
100 100 80 Bez ogranicenja – klasican SPF 
80>BW>50 
100>BW>80 
L1
L2

# Page 39

3977 TE ekstenzije ruting protokola 
• Na svim linkovima administratori konfigurišu 
koliko propusnog opsega može da se zauzme 
LSP-ovima 
• Svaki novi LSP sa odre đenim zahtevom za 
propusnim opsegom izaziva promenu slobodnog 
propusnog opsega na nekom linku => LSA se 
generiše => novo Dijkstra izra čunavanje 
• Zato postoji mehanizam kojim se ne reaguje na 
male promene slobodnog propusnog opsega 
• “Headend” ruter može da ima neta čnu sliku o 
zauze ću propusnog opsega u mreži 
78 OSPF-TE 
• RFC 3630 
• Nova vrsta LSA – Tip 10, koja se razmenjuje unutar 
jedne oblasti 
• LSA tip 10 nosi nove atribute za svaki link: 
– 1 - Link type (1 octet) 
– 2 - Link ID (4 octets) 
– 3 - Local interface IP address (4 octets) 
– 4 - Remote interface IP address (4 octets) 
–5 - Traffic engineering metric (4 octets) – TE metrika 
–6 - Maximum bandwidth (4 octets) – BW linka 
–7 - Maximum reservable bandwidth [bps] (4 octets) – adm 
konfiguriše 
–8 - Unreserved bandwidth (32 octets) – 8 vrednosti za 8 
preempt prioriteta 
–9 - Administrative group (4 octets) – afinitet, boja 

# Page 40

4079 Uspostavljanje TE-LSP 
• RSVP – Resource reSerVation Protocol – IntServ QoS 
arhitektura 
• Koristi se ekstenzija RSVP protokola – RSVP-TE 
• PATH poruke idu u downstream smeru, sa posebnim 
poljem LABEL_REQUEST u kojem su opisani parametri 
(ograni čenja) zahtevanog LSP 
• RESV poruke idu u upstream smeru i alociraju labele 
PATH 
PATH PATH RESV RESV 
Uspostavljanje TE-LSP 
80 


# Page 41

41Prosle đivanje Paketa 
81 
82 Reoptimizacija 
• Ako nestane T1, T2 će pre ći na kra ću putanju 
• MPLS TE ima “ make-before-brake ” optimizaciju 
• Postoji mehanizam koji spre čava “ double booking ”
• Reoptimizacija može da se pokrene ru čno, po isteku 
nekog tajmera, nakon nekog doga đaja T1 8Mbps 
T2 7Mbps 10 
10 10 10 
10 15 T1
T2

w# Page 42

4283 Fast reroute 
• Mehanizam kojim se omogu ćava brzo 
pronalaženje alternativne putanje (LSP) 
• Alternativni LSP se formira prilikom 
formiranja primarnog LSP 
• Vreme prebacivanja – nekoliko desetina 
ms 
84 L2TP 
• Layer 2 Tunneling Protocol 
• Nastao iz L2F i PPTP protokola 
• Najnovija verzija L2TPv3 (RFC 3931) 
• Služi za prenos razli čitih L2 tehnologija preko IP 
mreža 
– Ethernet 
– 802.1q 
– Frame Relay 
– HDLC 
– PPP 

# Page 43

4385 L2TP primena “compulsory remote 
access VPN” 
• Može da služi za pružanje ADSL ili dial-
VPN usluge 
• PPP sesija se od pojedina čnog korisnika 
produžuje do destinacione mreže kako bi 
se obezbedila autentifikacija i drugi servisi 
koje pruža PPP 
• Ure đaji koji u čestvuju u stvaranju tunela: 
– LAC - L2TP Access Concentrator 
– LNS – L2TP Network Server 
86 Osnovni mehanizam funkcionisanja 
compulsory remote access VPN 
PPP IP PPP IP IP L2TP 
Telefonska 
mreža, xDSL IP mreža 
provajdera Mreža korisnika LAC LNS 

# Page 44

4487 L2TPv3 
• Sa omogu ćavanjem prenosa razli čitih L2 
tehnologija omogu ćeno je i stvaranje site-
to-site L2 VPN preko IP mreža – L2TPv3 
pseudowire 
• L2TPv3 pseudowire može da prenosi ne-
IP saobra ćaj (AppleTalk, IPX) 
• L2TPv3 pseudowire može da se koristi 
kao mehanizam za tranziciju na IPv6 
88 IP in IP – RFC 2003 
• Namenjen za koriš ćenje u Mobile IP 


# Page 45

4589 Mobile IP 
• Home address: adresa iz mati čne mreže 
• Care-of address: adresa u novoj mreži 
– Foreign Agent CoA (svi mobilni čvorovi u stranoj 
mreži imaju istu CoA)
– Collocated CoA (mobilni čvorovi u stranoj mreži imaju 
razli čite adrese) 
• Home agent: ruter u mati čnoj mreži 
– Mobility binding table: parovi (home,care-of) 
• Foreign agent: ruter u novoj mreži 
– Visitor table: parovi(home address, home agent) 
90 Pronalaženje agenata 
• Mobilni agenti oglašavaju svoje prisustvo 
periodi čnim broadcast-om Agent Advertisement 
poruka. Agent Advertisement poruke sadrže 
jednu ili više care-of adresa. 
• Mobilni ure đaj koji prima Agent Advertisement 
može da otkrije da li je u pitanju home ili foreign  
agent tj da li je u svojoj ili stranoj mreži. 
• Ako mobilni ure đaj ne želi da čeka na periodi čne  
Agent Advertisment poruke, može da pošalje 
svoje Agent Solicitation poruke, kako bi inicirao 
slanje poruka od strane agenata. 

# Page 46

4691 Registracija 
• Ako je mobilni ure đaj na svojoj mreži, nastavi će da komunicira bez 
koriš ćenja IP mobility mehanizma. 
• Ako je mobilni ure đaj na stranoj mreži, registruje svoje prisustvo kod  
stranog agenta slanjem Registration Request poruka u kojima je 
home adresa mobilnog ure đaja i IP adresa njegovog home agenta. 
• Foreign agent prosle đuje registracione poruke ka home agentu 
mobilnog ure đaja i u te poruke dopisuje Care-of adresu koja se 
koristi u komunikaciji sa mobilnim ure đajem 
• Home agent kada primi registracionu poruku upisuje  uz IP adresu 
mobilnog ure đaja novu Care-of adresu za njega. 
• Home agent šalje acknowledgement foreign agentu i po činje da 
prosle đuje pakete ka mobilnom ure đaju. 
• Foreign agent prosle đuje odgovor mobilnom ure đaju. 
92 Proces registracije 


# Page 47

4793 Tok komunikacije 
• Ra čunari šalju pakete na home adresu. 
• Home agent presre će pakete i u mobility binding tabeli 
proverava da li je mobilni ure đaj u svojoj mreži ili nije. 
• Kada mobilni ure đaj nije u svojoj mati čnoj mreži, home 
agent vrši IP in IP tunelovanje i u spoljašnje zaglavl je 
kao source adresu stavlja svoju adresu, a kao 
destinacionu care-of adresu. 
• Kada enkapsulirani paket do đe do care-of adrese (agent 
ili sam ure đaj), dekapsulira se i prosle đuje do mobilnog 
ure đaja. 
• U suprotnom smeru paketi mogu da se šalju direktno ka 
ure đaju sa kojim se komunicira, a mogu i da se vrate 
kroz tunel do home agenta. 
ROI - Pavle Vuleti ć 94 Tok komunikacije 


# Page 48

48(LISP) 
• Locator/ID Separation Protocol (RFC 6830 
– januar 2013) 
• „dirty slate “ pristup promeni arhitekture 
Interneta (za krajnjeg korisnika nema 
nikakvih izmena) 
• Namenjen da reši: 
– problem broja ruta na Internetu 
– multihoming 
– mobilnost 
ROI – dr Pavle Vuleti ć 95 
(LISP) 
• EID – endpoint identifier 
• RLOC – Routing LOCator 
• Mapiranje EID u RLOC? 
• Internet ruting tabela – tabela RLOC 
ROI – dr Pavle Vuleti ć 96 
EIDs EIDd TCP/UDP DATA IP 
RLOCs RLOCd UDP LISP EIDs EIDd TCP/UDP DATA IP IP 
Slika preuzeta iz: Iannone, L., Saucez, D., & Bonaventur e, O. (2010). Implementing the Locator/ID Separation  Protocol: Design and experience. 
Computer Networks , 55 (4), 948–958. doi:10.1016/j.comnet.2010.12.017 








# Page 49

49ROI - Pavle Vuleti ć 97 GRE – RFC 2784 
• GRE – Generic routing encapsulation 
• Proizvoljni paketi 3. sloja se enkapsuliraju u 
proizvoljne pakete 3 sloja 
npr IPv4 
98 Osnovno GRE zaglavlje 
GRE flag-ovi 
• GRE flagovi i polja:
–Checksum Present (bit 0) 
–Key Present (bit 2) 
–Sequence Number Present (bit 3) 
–Version Number (bits 13–15): 0 naj češ će, 1 
za PPTP 
–Protocol Type 

# Page 50

5099 Opcione GRE ekstenzije 
GRE keepalive – za proveru rada tunela 
100 Secure VPN funkcije 
•Secure VPN ima slede će funkcije: 
–Poverljivost – Poverljivost podataka se 
dobija kriptovanjem sadržaja paketa. 
–Integritet podataka – Integritet podataka se 
čuva nekim mehanizmom koji potvr đuje da 
podaci u paketu nisu menjani tokom njegovog 
prolaza kroz Internet 
–Autentikacija porekla – Destinacija vrši 
autentikaciju pošiljaoca kako bi se osigurala 
da pakete dobija od odgovaraju ćeg izvora. 

# Page 51

51101 Zaštita saobra ćaja na razli čitim OSI 
slojevima 
102 Zaštita saobra ćaja na razli čitim OSI 
slojevima 
• Data link sloj: zaštita postoji samo na 
jednom mrežnom segmentu, ali je zašti ćen 
svaki paket na tom segmentu 
• Aplikacioni sloj: Zašti ćen je dati protokol 
aplikacionog sloja s kraja na kraj 
• Mrežni sloj: Zašti ćen je sav saobra ćaj s 
kraja na kraj 

# Page 52

52103 Protokoli za tunelovanje na OSI L3 
104 Kripto-mehanizmi pregled 


# Page 53

53105 Simetri čna enkripcija 
106 Algoritmi simetri čne enkripcije 
• DES vrši enkripciju 64-bitnih blokova. 
• Sa današnjim ra čunarima mogu će je razbijanje DES 
enkripcije za nekoliko dana 
• 3DES koristi dvostruku dužinu klju ča (112 bita) i izvodi tri 
DES operacije za redom 
• Advanced Encryption Standard (AES) je trenutno 
aktuelan standard za simetri čno kriptovanje klju čevima 
razli čite veli čine 128, 192 ili 256 bita kojima se kriptuju 
blokovi dužine 128, 192 ili 256 bits (mogu će su sve 
kombinacije dužine klju ča i veli čine blokova) 
• Drugi simetri čni algoritmi: IDEA, 

# Page 54

54107 DES 
108 DES inicijalna permutacija 


# Page 55

55ROI - Pavle Vuleti ć 109 Jedan krug DES algoritma 
ROI - Pavle Vuleti ć 110 DES F(R,K) 


# Page 56

56111 DES S-BOX 
112 DES na čini rada 
• Electronic Codebook 
Mode (ECB) 
• Svaki blok se 
nezavisno 
enkriptuje/dekriptuje 
• Relativno nesiguran 
na čin za duže 
poruke/pakete 
• Isti originalni blok –
isti kriptovani blok K EO
C
K D
OK EO
C
K D
OK EO
C
K D
O

# Page 57

57113 DES na čini rada 
• Cipher Block 
Chaining (CBC) 
• Isti blok originalnog 
teksta ne proizvodi isti 
kriptovani tekst 
• IV mora bezbedno da 
se razmeni, kao klju čK E
C
K DK EO
C
K DK EO
C
K D+ + +O
O O OIV 
IV + + +
114 DES na čini rada 
• Cipher Feedback 
(CFB) 
• J – jedinica prenosa –
obi čno 8 bita 
• Stream režim rada 
(nema paddinga) – ista 
dužina originalnog i 
kriptovanog teksta 
• Registri na po četku 
imaju IV K E K E K EShift < j bita Shift < j bita Shift < j bita 
O O O + + + C C C
K D K D K DShift < j bita Shift < j bita Shift < j bita 
O O+ + + C C C
O

# Page 58

58115 DES na čini rada 
• Output Feedback 
(OFB) 
• Sli čno kao CFB 
• Stream algoritam K E K E K EShift < j bita Shift < j bita Shift < j bita 
O O O + + + C C C
K D K D K DShift < j bita Shift < j bita Shift < j bita 
O O+ + + C C C
O
116 3DES 
• 2DES se ne primenjuje zbog Meet-in-the-
middle napada: 
– C=E K1(E K2(O)) – ukupna dužina klju ča 2xn – 22n 
broj pokušaja 
– Ako napada č poznaje C i O, može da proba da 
napravi E Kn (O) i D Kn (C) sa sve kn i da ih upari –
2n+1 pokušaja 
• Varijante 3DES: 
– EEE C=E k3 (E k2 (E k1 (O))) – 168 bita 
– EDE C=E k3 (D k2 (E k1 (O))) 
– EDE – 2DES - C=E k1 (D k2 (E k1 (O))) – 112 bita 

# Page 59

59117 Asimetri čna ekripcija 
Najpoznatiji algoritmi asimetri čne enkripcije su RSA (Ron Rivest, Adi 
Shamir, and Leonard Adleman) i El Gamal algoritam. 
118 RSA 
• Izaberu se dva velika prosta broja pi q
•n=pq 
• Totient : phi=(p-1)(q-1) 
• Prona đe se ceo broj e takav da je 1<e<phi 
i e i phi su uzajamno prosti 
•e je javni klju č
• Izra čuna se dtakvo da je de=1mod(phi) 
•d je privatni klju č

# Page 60

60119 RSA kriptovanje i dekriptovanje 
• Kriptovanje: 
–c=m emod n 
• Dekriptovanje 
–m=c dmod n 
• Primer 
– p=61, q=53 => n=3233, phi=3120 
– e=17 => d=2753 
– c=123 => c=123 17 mod 3233 = 855 = m 
– m=855 2753 mod 3233 = 123 
• Realni RSA klju čevi 1024 bita i više 
120 Hash funkcije primena 


# Page 61

61121 MD5 – RFC1321 
• Poruka mora da bude 
nx512 bita 
• 128 bit hash 
• A,B,C,D – 32 bita 
• <<< Left shift 
• + - sabiranje po 
modulu 2 32 
• F – F,G,H,I – 4 runde 
za svaki blok od 128 
122 Hashing algoritm i
• Dva najrasprostranjenija hash algoritma: 
MD5 i SHA 
• HMAC verzije – sa klju čem:
–HMAC-MD5 – Koristi 128-bit klju č. Izlaz je 
128-bit hash. 
–HMAC-SHA-1 – Koristi 160-bit klju č. Izlaz je 
160-bit hash. 

# Page 62

62123 Razmena klju čeva – Diffie-Hellman 
124 Razmena klju čeva – Diffie-Hellman 
p i g su prosti brojevi, g je obi čno 2, a p je veliki (pseudo)prost broj. 
Primer: p=11, g=2, Xa = 9, Xb = 4. 
Ya = 2 9 (mod 11) Yb=2 4(mod 11) 
Ya = 6 Yb=5 
K=Yb Xa (mod 11) K=Ya Xb (mod 11) 
K=5 9(mod 11) = 1953125(mod 11) K=6 4(mod 11) = 1296(mod 11) 
K=9 K=9 

# Page 63

63125 DH problem: Man-in-the-middle 
Odbrana: jaka autentikacija A i B, enkripcija mater ijala simetri čnim ili 
privatnim klju čem,... A B
Public A Public B 
Kab 
M
A BPublic A Public MA 
Kam 
Public B Public M 
Kbm 
126 Replay napad 
Odbrana: postojanje pseudo-slu čajnih “session token”-a ili “nonce”-aM B
Ja sam A Ko si ti?A B
Ja sam A Ko si ti?
M BA BKo si ti? 12361524 
Ja sam A 12361524 MD5
Ko si ti? 653485 
Ja sam A 12361524 MD5

# Page 64

64127 Gde se koriste algoritmi za 
kriptovanje 
• Klju čevi asimetri čnih algoritama su mnogo duži 
od klju čeva simetri čnih i njihovo izvršavanje je 
za više redova veli čine sporije. 
• Približno: simetri čnom algoritmu sa klju čem 
dužine 64 bita odgovara asimetri čni algoritam sa 
klju čem dužine 768 bita (za zaštitu ekvivalentne 
kriptografske snage) 
• Asimetri čni algoritmi se koriste za razmenu 
kriptografskog materijala 
• Simetri čni algoritmi se koriste za zaštitu 
saobra ćaja 
128 Preporuka za dužinu klju ča
• Ra čuna se na osnovu broja operacija 
potrebnih za razbijanje algoritma 
isprobavanjem klju čeva u nekom 
vremenskom periodu (npr 20 god) 
• RFC preporuka: 1996. – 90 bita 
• Broj bita pove ćati za 2/3 svake godine ako 
se ra čuna da se brzina ra čunara pove ćava 
po Murovom zakonu. 

# Page 65

65129 Preporu čene veli čine klju čeva 
•n- broj operacija za simetri čni algoritam 
nad jednim blokom 
•k- broj bita u klju ču simetri čnog algoritma 
• Broj operacija za razbijanje = n2 k
•kp - broj bita u klju ču asimetri čnog 
algoritma ))) (ln(ln( ) ln( 92 . 1 (3 202 .0 2kp kp ke n⋅=
ROI - Pavle Vuleti ć 130 Preporu čene veli čine klju čeva 
• Pretpostavke: 
– Ra čunari se razvijaju tempom kao do sada 
– Nema napretka u relevantnim oblastima 
matematike 


# Page 66

66131 IPsec 
• Skup protokola i metoda opisanim u RFC: 2401 
(4301) i brojnim drugim RFC dokumentima 
• Sastavni deo IPv6 
• Osnovne komponente:
– Authentication Header 
– Encapsulating Security Payload 
– IKE/ISAKMP 
• Dva režima prenosa paketa 
– Tunel 
– Transport 
132 Sigurnosna asocijacija - SA 
• SA je skup pravila i metoda koje će IPsec strane 
u komunikaciji koristiti za zaštitu saobra ćaja 
izme đu njih. 
• SA sadrži sve sigurnosne parametre potrebne 
za siguran transport paketa kroz mrežu 
koriš ćenjem IPsec 
• Uspostavljanje SA je preduslov za IPSec zaštitu 
saobra ćaja . 
• SA su uvek unidirekcione. Za zaštitu saobra ćaja 
u oba smera, potrebno je da postoje dve 
paralelne SA. 
• SA se čuvaju u SA database (SADB) 
• Skup pravila se čuva u Security policy DB SPDB 

# Page 67

67133 SA 
ESP TUNNEL - SPI_IN ESP TUNNEL - SPI_OUT 
MY_EXTERNAL_IP PEER_EXTERNAL_IP 
HOST A HOST B 
134 SA 
• Za svaki poseban protokol koji se koristi 
postoji posebna SA 
• Parametri koji postoje u SA: 
– Algoritam za autentikaciju/enkripciju, dužina 
klju ča, trajanje klju ča
– Klju čevi koji služe za autentikaciju (HMAC) i 
enkripciju 
– Specifikaciju saobra ćaja koji će biti podvrgnut 
datoj SA 
– IPSec protokol za enkapsulaciju (AH or ESP) i 
režim rada (tunel ili transport) 

# Page 68

68ROI - Pavle Vuleti ć 135 Authentication header - AH 
0                        7|8                          15|16                                                     31 
Next Header Payload Length RESERVED 
Security Parameter Index (SPI) 
Sequence Number Field 
Authentication Data (variable) 
 
136 AH 
• IP Authentication Header (AH) se koristi 
za 
– Obezbe đivanje integriteta bez ostvarivanja 
konekcije 
– Autentikacije porekla IP paketa 
– Zaštitu od napada ponavljanjem 
• Delovi IP zaglavlja koji se menjaju tokom 
prolaska kroz mrežu ne mogu da budu 
zašti ćeni (TTL, Flags, Fragment offset, 
TOS) 

# Page 69

69137 Encapsulation Security Payload -
ESP 
Security Parameters Index (SPI) 
Sequence Number 
Payload Data* (variable) 
              Padding (0-255 bytes) 
 Pad Length Next Header 
Authentication Data (variable) 
 
138 ESP 
• ESP pruža slede će servise:
– Poverljivost 
– Autentikaciju porekla 
– Obezbe đivanje integriteta bez ostvarivanja 
konekcije 
– Anti-replay servis
– Ograni čenu zaštitu od analize tokova u mreži 
(kada se koristi tunel mod) 

# Page 70

70139 ESP i AH u transportnom modu 
• AH autentifikuje ceo originalni IP paket 
• ESP autentifikuje samo “data” deo 
originalnog paketa 
140 ESP i AH u tunel modu 
• AH autentifikuje ceo originalni IP paket i 
spoljašnje zaglavlje 
• ESP autentifikuje originalni paket i ESP 
zaglavlje 


# Page 71

71141 Kombinacije dve SA 
Host 1 Host 2 Internet Security 
Gateway 2 Security 
Gateway 1 
SA1(Tunnel) 
SA2(Tunnel) Host 1 Host 2 Internet Security 
Gateway 2 Security 
Gateway 1 
SA1(Tunnel) 
SA2(Tunnel) 
Host 1 Host 2 Internet Security 
Gateway 2 Security 
Gateway 1 
SA1(Tunnel) 
SA2(Tunnel) Host 1 Host 2 Internet Security 
Gateway 2 Security 
Gateway 1 
SA1(Tunnel) 
SA2(Tunnel) 
ROI - Pavle Vuleti ć 142 Router B 
Router 10.0.3.5 10.0.0.7 Source Destin 
IP TCP DATA 
10.0.3.5 10.0.0.7 IP TCP DATA 10.0.3.5 10.0.0.7 IP TCP DATA 
10.0.3.5 10.0.0.7 IP TCP DATA 
10.0.3.5 10.0.0.7 IP TCP DATA 10.0.3.5 10.0.0.7 IP TCP DATA ESP  IP 
Kriptovano 192.168.1.254 192.168.2.1 10.0.3.5 
10.0.0.7  A 
A
B192.168.1.254 
192.168.2.1 
ESP  IP 192.168.1.254 192.168.2.1 

# Page 72

72143 IKE/ISAKMP 
• IKEv1 – RFC 2409 
• ISAKMP – RFC 2407, 2408 
• IKEv2 – RFC 4306 (obsoletes 2407, 2408, 2409) 
• IKE je hibridni protokol koji je nastao iz Oakley i  
Skeme mehanizma za razmenu klju čeva i koristi 
Internet Security Association and Key 
Management Protocol (ISAKMP) okvir kao 
mehanizam za razmenu poruka 
• Oakley i Skeme mehanizmi su zasnovani na DH 
razmeni klju čeva 
144 IKE 
• Osnovni Diffie-Hellman mehanizam ne pruža 
autentikaciju u česnika u razmeni klju čeva.
• Nedostatak autentikacije omogu ćava Man-in-
the-middle napade. 
• Autentikacija se ostvaruje na razli čite na čine: 
– unapred razmenjenim klju čevima 
– digitalnim potpisima 
– Sertifikatima 
• U IKE protokol su uklju čene i druge zaštite od 
replay,... Napada 
• PFS – Perfect Forward Secrecy 

# Page 73

73145 X.509 v3 digitalni sertifikat 
146 IKE mehanizam
• IKE razmena klju ča se sastoji od dve faze: 
– Main mode 
– Quick mode 
• U Main mode fazi se dobija klju č koji služi 
za zaštitu IKE saobra ćaja (ISAKMP SA) 
• U Quick mode fazi se dobija klju č koji služi 
za zaštitu korisni čkog saobra ćaja (IPsec 
SA) 

# Page 74

74147 IKEv1 sa unapred razmenjenim 
klju čevima 
• Main mode 
• Quick mode 
148 IKEv2 – RFC 4306 
• Jednostavniji 
– Samo jedna vrsta razmene klju čeva 
– Manje kriptografskih algoritama 
• Stabilniji 
• Bolja zaštita od DoS napada 
• Malo realizovanih implementacija 

# Page 75

75IPsec Site-to-Site VPN 
Konfiguracija klijentskih strana 
interface Loopback0 
ip address 192.168.1.1 255.255.255.0 
!
interface FastEthernet0 
ip address 192.168.12.1 255.255.255.0 
speed auto 
!
ip route 0.0.0.0 0.0.0.0 192.168.12.2 
!
interface Loopback0 
ip address 192.168.5.1 255.255.255.0 
!
interface FastEthernet0 
ip address 192.168.45.5 255.255.255.0 
speed auto 
!
ip route 0.0.0.0 0.0.0.0 192.168.45.4 
!R1 
R5 

# Page 76

76IPsec konfiguracija 
!Konfiguracija ISAKMP SA 
crypto isakmp policy 10 
hash md5 
authentication pre-share 
crypto isakmp key vpnuser address 192.168.34.4 
!
!Konfiguracija IPsec SA 
crypto ipsec transform-set myset esp-des esp-md5-hm ac 
!
crypto map mymap 10 ipsec-isakmp 
set peer 192.168.34.4 
set transform-set myset 
match address 100 
!
access-list 100 permit ip 192.168.1.0 0.0.0.255 192 .168.5.0 0.0.0.255 
!
interface FastEthernet0/1 
ip address 192.168.23.2 255.255.255.0 
duplex auto 
speed auto 
crypto map mymap R2 
Pokretanje IPsec 
R1#ping 
Protocol [ip]: 
Target IP address: 192.168.5.1 
Repeat count [5]: 
Datagram size [100]: 
Timeout in seconds [2]: 
Extended commands [n]: y 
Source address or interface: 192.168.1.1 
Type of service [0]: 
Set DF bit in IP header? [no]: 
Validate reply data? [no]: 
Data pattern [0xABCD]: 
Loose, Strict, Record, Timestamp, Verbose[none]: 
Sweep range of sizes [n]: 
Type escape sequence to abort. 
Sending 5, 100-byte ICMP Echos to 192.168.5.1, time out is 2 seconds: 
Packet sent with a source address of 192.168.1.1 
.!!!! 
Success rate is 80 percent (4/5), round-trip min/av g/max = 44/75/92 ms 

# Page 77

77Nadgledanje IPsec (1) 
R2#sh crypto isakmp sa 
dst             src             state          conn -id slot status 
192.168.34.4    192.168.23.2    QM_IDLE              2    0 ACTIVE 
R2#sh crypto ips sa 
interface: FastEthernet0/1 
Crypto map tag: mymap, local addr 192.168.23.2 
protected vrf: (none) 
local  ident (addr/mask/prot/port): ( 192.168.1.0/255.255.255.0/0/0 )
remote ident (addr/mask/prot/port): ( 192.168.5.0/255.255.255.0/0/0 )
current_peer 192.168.34.4 port 500 
PERMIT, flags={origin_is_acl,} 
#pkts encaps: 4, #pkts encrypt: 4, #pkts digest: 4 
#pkts decaps: 4, #pkts decrypt: 4, #pkts verify: 4 
#pkts compressed: 0, #pkts decompressed: 0 
#pkts not compressed: 0, #pkts compr. failed: 0 
#pkts not decompressed: 0, #pkts decompress failed:  0 
#send errors 1, #recv errors 0 
local crypto endpt.: 192.168.23.2, remote crypto en dpt.: 
192.168.34.4 
path mtu 1500, ip mtu 1500, ip mtu idb FastEthernet 0/1 
current outbound spi: 0x23D2554C (600986956) 
… nastavak na slede ćem slajdu 
Nadgledanje IPsec (2) 
… nastavak sa prethodnog slajda     
inbound esp sas: 
spi: 0x27DCF183 (668791171) 
transform: esp-des esp-md5-hmac , 
in use settings ={Tunnel, } 
conn id: 2002, flow_id: SW:2, crypto map: mymap 
sa timing: remaining key lifetime (k/sec): 
(4524281/2843) 
IV size: 8 bytes 
replay detection support: Y 
Status: ACTIVE 
inbound ah sas: 
inbound pcp sas: 
outbound esp sas: 
spi: 0x23D2554C (600986956) 
transform: esp-des esp-md5-hmac , 
in use settings ={Tunnel, } 
conn id: 2001, flow_id: SW:1, crypto map: mymap 
sa timing: remaining key lifetime (k/sec): 
(4524281/2842) 
IV size: 8 bytes 
replay detection support: Y 
Status: ACTIVE 
outbound ah sas: 
outbound pcp sas: 

# Page 78

78Packet capture 
156 Rutiranje preko IPsec 
• IPsec ne prenosi multicast? 
• GRE – za prenos paketa protkola 
rutiranja 


# Page 79

79157 IKE dodaci 
• Faza 1.5 
– Xauth 
– Mode konfiguracija 
• NAT Traversal 
• IKE DPD (dead peer detection) 
– DPD šalje keepalive pakete kada nema saobra ćaja 
kroz SA 
– DPD mehanizam može da bude periodi čan ili po 
pozivu 
158 NAT Traversal 
• Problem kada se izme đu IPsec ure đaja vrši PAT 
ili NAT overload (brojevi portova u zaglavlju 
transportnog sloja se ne vide) 
• NAT-T detekcija 
• NAT-T akcija 


# Page 80

80159 NAT-T detekcija 
• Za vreme IKE faze 1 ure đaji detektuju dva doga đaja: 
– Podršku za NAT-T
– Postojanje NAT duž putanje 
• Za detekciju podrške za NAT-T razmenjuje se vendor ID 
string u okviru IKE poruka 
• Postojanje NAT se detektuje tako što se pošalje hash(IP 
adrese, portovi) u okviru NAT discovery (NAT-D) delova 
IKE poruke. 
• Ako je hash koji je izra čunat na destinaciji jednak 
poslatom hash-u – nema NAT-a
160 NAT-T akcija i enkapsulacija 
• NAT-T akcija : Tokom IKE faze 2 se odlu čuje da li će da se 
primeni NAT-T
• UDP enkapsulacija IPsec paketa : Ako se koristi NAT-T 
dodatno UDP zaglavlje se ume će izme đu spoljašnjeg IP 
zaglavlja i IPsec zaglavlja 
• UDP checksum : Novo UDP zaglavlje ima checksum 
vrednost 0, kako se ne bi proveravala ova vrednost 


# Page 81

81161 Kreiranje IPsec SA 
• IPsec SA može da se kreira: 
– Po potrebi, kada nai đe paket koji pripada 
datoj SA 
• Manje zauze će resursa 
• Inicijalno kašnjenje veliko 
• Potencijalno ve ći broj rekey-a
– Da bude permanentna, bez obzira na 
saobra ćaj 
162 SSL – Secure Sockets Layer 
• SSL v1,v2,v3. Verzije v1 i v2 se smatraju 
za nesigurne 
• Transport Layer Security – TLS (RFC 
2246), v1.1(RFC 4346), v1.2 (RFC 5246) 
• SSL služi za zaštitu TCP protokola 
• SSL se koristi kod HTTPS, FTPS, POP3S, 
SMTPS 
• Može da se koristi za zaštitu pojedina čnih 
protokola ili celokupnog saobra ćaja 

# Page 82

82163 SSL slojevi 
SSL Record layer 
TCP 
IP Data 
SSL 
TCP 
IP Hands 
hake Alert Chg 
Ciph 
Spec Data 
164 SSL Record Layer 
• Fragmentacija 
• Kompresija 
• Message Authentication Code 
• Enkripcija/dekripcija 

# Page 83

83165 SSL Protokoli 
Handshake – za uspostavljanje SSL sesija 
• Alert – Signalizacija gresaka 
• Change Cipher Specification –
signalizacija da su naredne SSL poruke 
kriptovane 
• Application data protocol (HTTP, FTP, 
POP3, IMAP, SMTP) 
166 SSL Handshake (no client auth) 


# Page 84

84167 SSL Handshake (w client auth) 
Klijent Server 
ClientHello (predlog parametara zaštite i kompresij e)
ServerHello (specifikacija prihvaćenog protokola + sl. broj)  
CertificateRequest 
ServerHelloDone 
ClientKeyExchange (E[Premaster secret + sl broj])
ChangeCipherSpec 
Finished 
ChangeCipherSpec 
Finished Certificate (Public Key) 
Certificate 
CertificateVerify (tekst potpisan privatnim ključem  klijenta)
168 Na čini rada SSL VPN 
• Svaka aplikacija zasebna zaštita 
• Pristup preko weba (clientless) – port 
forwarding konfigurisan na centralnoj 
lokaciji 
• Pristup kroz web, pa download klijenta koji 
je validan za vreme trajanja jedne SSL 
VPN sesije 
• Unapred instaliran klijent 

# Page 85

85ROI - Pavle Vuleti ć 169 Clientless (port forwarding) 
SSL VPN rute 
pavle@pavle-ThinkPad-T420 :~$ route 
Kernel IP routing table 
Destination     Gateway         Genmask         Fla gs Metric Ref    Use Iface 
default         192.168.1.1     0.0.0.0         UG    600    0        0 wlp3s0 
link-local      *               255.255.0.0     U     1000   0        0 wlp3s0 
192.168.1.0     *               255.255.255.0   U     600    0        0 wlp3s0 
pavle@pavle-ThinkPad-T420 :~$ route 
Kernel IP routing table 
Destination     Gateway         Genmask         Fla gs Metric Ref    Use Iface 
default         192.168.1.1     0.0.0.0         UG    600    0        0 wlp3s0 
10.8.0.0        *               255.255.0.0     U     50     0        0 tun0 
91.187.128.0    10.8.0.1        255.255.224.0   UG    50     0        0 tun0 
147.91.0.0      10.8.0.1        255.255.0.0     UG    50     0        0 tun0 
vpn.amres.ac.rs 192.168.1.1     255.255.255.255 UGH    600    0        0 wlp3s0 
160.99.0.0      10.8.0.1        255.255.0.0     UG    50     0        0 tun0 
link-local      *               255.255.0.0     U     1000   0        0 wlp3s0 
192.168.1.0     *               255.255.255.0   U     600    0        0 wlp3s0 

# Page 86

86
172 SSL literatura 
•http://www.networkworld.com/subnets/cisco/072507-ch 10-
deploying-vpns.html?page=1 

