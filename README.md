# CSEProgrammingAssignment2

- "Secure" (for an undergrad class) client-server file transfer
- Asymmetric (RSA) "CP1" and symmetric (AES) "CP2" protocols
- Super fun to watch the packets in Wireshark ("HELLO CP1 V1 NONCE=..." or "CERT?")
- Just use `sftp` instead jeez

This is PA2 for 50.005 Computer System Engineering 2019. If you are taking this class in the future please don't copy the code
here. (Among other things, the certs will have expired by then.)

This is an IntelliJ project. If using Eclipse you may be able to import it.

You must run the JVM with the `-ea` (enable assertions) argument to properly handle error cases. Or use the `srv_cp{1,2}.sh` scripts.

Thanks to my almost-partner in crime, Yi Xuan, for countless hours of Extreme Pair Programming (tm) and whiteboarding.

[Please do not use this algorithm to secure real file transfers over the public internet.](https://security.stackexchange.com/questions/18197/why-shouldnt-we-roll-our-own)
