package com.github.luglimaccaferri.qbic.http;

import com.github.luglimaccaferri.qbic.Core;
import com.github.luglimaccaferri.qbic.http.controllers.AuthController;
import com.github.luglimaccaferri.qbic.http.controllers.NodesController;
import com.github.luglimaccaferri.qbic.http.models.HTTPError;
import com.github.luglimaccaferri.qbic.http.models.Ok;
import com.github.luglimaccaferri.qbic.utils.Security;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.FormBody;
import okhttp3.Request;
import okhttp3.RequestBody;

import java.io.IOException;
import java.net.NoRouteToHostException;
import java.util.concurrent.CompletableFuture;

import static com.github.luglimaccaferri.qbic.http.models.ProtectedRoute.route;
import static spark.Spark.*;

public class Router {

    public Router(short port){ port(port); }
    public void kill(){ stop(); }

    public void ignite() {

        CompletableFuture.runAsync(this::broadcastPublicKey);

        before((req, res) -> {

            res.header("Access-Control-Allow-Origin", "http://localhost:8080"); // debug da togliere in prod
            res.header("Access-Control-Allow-Headers", "*"); // debug
            res.header("Access-Control-Allow-Credentials", "true");
            res.type("application/json");
            req.attribute("parsed-body", JsonParser.parseString(req.body()));

            String contentType = req.headers("Content-Type");
            String requestMethod = req.requestMethod();
            String url = req.url();

            Core.logger.warn(requestMethod + " " + url);
            Core.logger.warn(contentType);

        });

        options("/*", (req, res) -> {

            String accessControlRequestHeaders = req.headers("Access-Control-Request-Headers");
            if (accessControlRequestHeaders != null) {
                res.header("Access-Control-Allow-Headers", accessControlRequestHeaders);
            }

            String accessControlRequestMethod = req.headers("Access-Control-Request-Method");
            if (accessControlRequestMethod != null) {
                res.header("Access-Control-Allow-Methods", accessControlRequestMethod);
            }
            return "OK";

        });

        // root paths

        get("/", (req, res) -> {
            return Ok.SUCCESS.toResponse(res);
        });
        route(true).get("/auth", AuthController.index);

        get("/nodes", NodesController.index);

        // derived paths

        path("/auth", () -> {
            route(new String[]{"username", "password"}).post("/login", AuthController.login);
        });

        get("*", (req, res) -> HTTPError.NOT_FOUND.toResponse(res));

        exception(HTTPError.class, (e, req, res) -> {
            res.status(e.getErrorCode());
            res.body(e.print());
        });

    }

    private void broadcastPublicKey(){

        JsonArray nodes = Core.getConfig().getAsJsonArray("nodes");

        System.out.println("broadcasting to nodes...");

        nodes.forEach(node -> {

            JsonObject obj = node.getAsJsonObject();
            String host = obj.get("host").getAsString();
            String url = String.format("%s/auth/public-key", host);

            System.out.printf("broadcasting to %s%n", url);

            RequestBody body =  new FormBody.Builder()
                    .add("public-key", Security.bytesToHex(Core.KEYS.getPublic().getEncoded())).
                    build();
            Request request = new Request.Builder()
                    .url(url)
                    .post(body)
                    .build();

            try {
                Core.getHttpClient().newCall(request).execute().close();
            } catch (IOException e) {
                if(e instanceof NoRouteToHostException) System.out.println("no route to host?");
                else e.printStackTrace();
            }

        });

    }

}
