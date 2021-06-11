package com.github.luglimaccaferri.qbic.http;

import com.github.luglimaccaferri.qbic.Core;
import com.github.luglimaccaferri.qbic.http.controllers.AuthController;
import com.github.luglimaccaferri.qbic.http.models.HTTPError;
import com.github.luglimaccaferri.qbic.http.models.Ok;
import com.github.luglimaccaferri.qbic.utils.Security;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import okhttp3.FormBody;
import okhttp3.Request;
import okhttp3.RequestBody;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

import static com.github.luglimaccaferri.qbic.http.models.ProtectedRoute.route;
import static spark.Spark.*;

public class Router {

    public Router(short port){ port(port); }
    public void kill(){ stop(); }

    public void ignite() {

        CompletableFuture.runAsync(this::broadcastPublicKey);

        before((req, res) -> {

            res.type("application/json");

            String contentType = req.headers("Content-Type");
            String requestMethod = req.requestMethod();
            String url = req.url();

            Core.logger.info(requestMethod + " " + url);
            Core.logger.info(contentType);

        });

        // root paths

        get("/", (req, res) -> {
            return Ok.SUCCESS.toResponse(res);
        });
        route(true).get("/auth", AuthController.index);

        // derived paths

        path("/auth", () -> {
            route(new String[]{"username", "password"}).post("/login", AuthController.login);
        });

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
            RequestBody body =  new FormBody.Builder()
                    .add("public-key", Security.bytesToHex(Core.KEYS.getPublic().getEncoded())).
                    build();
            Request request = new Request.Builder()
                    .url(
                            String.format("%s/auth/public-key", host)
                    )
                    .post(body)
                    .build();

            try {
                Core.getHttpClient().newCall(request).execute();
            } catch (IOException e) {
                e.printStackTrace();
            }

        });

    }

}
