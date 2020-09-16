# TBIBS for TLS in Java

### Setup
1. Open the maven project using the pom.xml

2. mark following directories as source:
    + hibe/src/
    + JCAlber/src/
    + src/

3. mark following directories as test-source:
    + hibe/test/
    + JCAlber/src-test/
    + test/

4. mark following directory as resource:
    + resources/

5. get evaluation editions for JCA/JCE and ECCelerate and
 iSaSiLk
 from: https://jce.iaik.tugraz.at/products/core-crypto-toolkits/
 
6. extract to directory libs/ the following:
    + lib-signed/iaik_jce_full.jar
    + iaik_eccelerate.jar
    + iaik_eccelerate_ssl.jar
    + iaik_ssl_demo.jar

7. add libraries in lib/ to the classpath

8. Add following alias to /etc/hosts:
```
    127.0.0.1    DEMO-CA
    127.0.0.1    DEMO-CDN
    127.0.0.1    DEMO-SERVER
```

9. Run src/master/MasterServer.java first to create a keystore
 (you can choose the server hostname arbitrarily)
 
10. Run the Junit tests to verify that your setup was
 successful
