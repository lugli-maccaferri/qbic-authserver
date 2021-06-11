package com.github.luglimaccaferri.qbic;

import com.github.luglimaccaferri.qbic.data.cli.CliParser;
import com.github.luglimaccaferri.qbic.data.cli.CliShortItem;
import com.github.luglimaccaferri.qbic.data.models.misc.User;
import com.github.luglimaccaferri.qbic.data.mysql.Connector;
import com.github.luglimaccaferri.qbic.errors.users.ExistingUserException;
import com.github.luglimaccaferri.qbic.http.Router;
import com.github.luglimaccaferri.qbic.utils.RandomString;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.OkHttpClient;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class Core {

    private final Router router;
    private static JsonObject config;
    private final static OkHttpClient httpClient = new OkHttpClient.Builder().connectTimeout(5, TimeUnit.SECONDS).build();
    public static final Logger logger = Log.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    private boolean initialized = false;

    public static String CONFIG_PATH = System.getProperty("user.dir") + "/" + (String) CliParser.options.get("config").value();
    public static String KEYS_PATH = System.getProperty("user.dir") + "/keys";
    public static KeyPair KEYS;

    public Core(){

        System.out.println("initializing qbic...");
        System.out.println("config file: " + CliParser.options.get("config").value());
        CliShortItem port = (CliShortItem) CliParser.options.get("port");
        System.out.println("http port: " + port.value());
        this.router = new Router(port.value()); // sono sicuro che sia short

    }

    public static JsonObject getConfig(){ return config; }
    public static OkHttpClient getHttpClient() { return httpClient; }

    public void init(){

        if(this.initialized) return;

        try{

            // directory chiave pubblica/privata
            Files.createDirectories(Path.of(KEYS_PATH)); // createDirectories non throwa niente se la directory esiste già

            if(!Files.exists(Path.of(CONFIG_PATH)))
                Files.copy(
                        Objects.requireNonNull(
                                getClass().getClassLoader().getResourceAsStream("config.json")),
                        Path.of(CONFIG_PATH)
                );

            config = (JsonObject) JsonParser.parseReader(new FileReader(CONFIG_PATH));
            Connector mysqlConnector = Connector.connect(config.getAsJsonObject("mysql"));

            String rootUserUsername = (String) CliParser.options.get("root-user").value();
            User rootUser = User.from(rootUserUsername);

            if(rootUser == null){

                // con l'utente root viene anche generata la chiave privata (magari troviamo un metodo migliore per detectare l'installazione)
                System.out.println("===== IMPORTANT =====");
                System.out.printf("generating '%s' as root user%n", rootUserUsername);
                String rootUserPass = RandomString.generateAlphanumeric(20);

                User root = generateRootUser(rootUserUsername, rootUserPass);

                System.out.printf(
                        "generated root user '%s' identified by %s and with UUID %s%n"
                        , root.getUsername(), rootUserPass, root.getUUID());
                System.out.println("save this info a$ap because you won't see this message ever again!");
                System.out.println("generating private/public key pair...");

                generatePrivatePublicPair();
                System.out.printf("dumped RSA key pair at %s%n", KEYS_PATH);
                System.out.println("==========");

            } else System.out.println("skipping root user creation...");

            byte[] publicBytes = Files.readAllBytes(Path.of(KEYS_PATH + "/public.key"));
            byte[] privateBytes = Files.readAllBytes(Path.of(KEYS_PATH + "/private.key"));
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicBytes); // pubblica = X.509
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateBytes); // privata = PKCS8

            KEYS = new KeyPair(
                    KeyFactory.getInstance("RSA").generatePublic(publicSpec),
                    KeyFactory.getInstance("RSA").generatePrivate(privateSpec)
            );

            this.router.ignite();
            this.initialized = true;
            System.out.println("qbic has been successfully started!");

        }catch(Exception e){

            logger.warn("startup error");
            Connector.connection.disconnect();
            this.router.kill();
            e.printStackTrace();

        }

    }

    User generateRootUser(String rootUserUsername, String rootUserPassword) throws ExistingUserException, ExecutionException, InterruptedException {

        String rootUserUUID = UUID.randomUUID().toString();
        return User.createInstance(rootUserUUID, rootUserUsername, rootUserPassword, (byte) 1);

    }

    void generatePrivatePublicPair() throws IOException, NoSuchAlgorithmException {

        Files.deleteIfExists(Path.of(KEYS_PATH + "/public.key"));
        Files.deleteIfExists(Path.of(KEYS_PATH + "/private.key"));

        // 2048 bit key per ridere
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048); // magari custom
        KeyPair kp = kpg.generateKeyPair();
        Key publicKey = kp.getPublic(),
            privateKey = kp.getPrivate();

        FileOutputStream writer = new FileOutputStream(KEYS_PATH + "/public.key");
        writer.write(publicKey.getEncoded());
        writer = new FileOutputStream(KEYS_PATH + "/private.key");
        writer.write(privateKey.getEncoded());
        writer.close();

        return;

    }

}
