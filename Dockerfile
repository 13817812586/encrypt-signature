FROM openjdk:11
WORKDIR /opt
ADD target/encrypt-signature-0.0.1-SNAPSHOT.jar .
EXPOSE 8080
CMD java -jar encrypt-signature-0.0.1-SNAPSHOT.jar