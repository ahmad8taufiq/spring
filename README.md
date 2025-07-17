./mvnw spring-boot:run

keytool -import -alias mycert -file cert-00 -keystore truststore.jks -storepass Coin10c10000
keytool -import -alias intermediate1 -file cert-01 -keystore truststore.jks -storepass Coin10c10000

keytool -import -alias mycert -file cert-00 -keystore /Users/ahmadtaufiq/truststore.keystore -storepass Coin10c10000
keytool -import -alias intermediate1 -file cert-01 -keystore /Users/ahmadtaufiq/truststore.keystore -storepass Coin10c10000

keytool -list -keystore truststore.jks -storepass Coin10c10000

curl --location 'http://localhost:8080/api/sign'
