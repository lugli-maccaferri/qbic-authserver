package com.github.luglimaccaferri.qbic.http;

import com.github.luglimaccaferri.qbic.Core;
import com.github.luglimaccaferri.qbic.http.controllers.AuthController;
import com.github.luglimaccaferri.qbic.http.models.HTTPError;
import com.github.luglimaccaferri.qbic.http.models.Ok;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.net.URI;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static com.github.luglimaccaferri.qbic.http.models.ProtectedRoute.route;
import static spark.Spark.*;

public class Router {

    public Router(short port){ port(port); }
    public void kill(){ stop(); }

    public void ignite() throws ExecutionException, InterruptedException {

        CompletableFuture.runAsync(() -> {
            try {
                broadcastPublicKey();
            } catch (ExecutionException | InterruptedException e) {
                e.printStackTrace();
            }
        });

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

    private void broadcastPublicKey() throws ExecutionException, InterruptedException {

        JsonArray nodes = Core.getConfig().getAsJsonArray("nodes");
        ArrayList<CompletableFuture<HttpResponse<String>>> futs = new ArrayList<CompletableFuture<HttpResponse<String>>>();

        System.out.println("broadcasting to nodes...");

        nodes.forEach(node -> {

            JsonObject obj = node.getAsJsonObject();
            String host = obj.get("host").getAsString();
            HttpRequest request = HttpRequest
                    .newBuilder(
                        URI.create(
                            String.format("%s/auth/public-key", host))
                    )
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(5))
                    .POST(HttpRequest.BodyPublishers.ofString("public-key=" + Core.KEYS.getPublic().toString()))
                    .build();

                // migliorare sta cosa, va fatta simile ad un Promise.all
                // System.out.printf("broadcasting to node %s...%n", obj.get("host"));
            try {
                Core.getHttpClient().sendAsync(request, HttpResponse.BodyHandlers.ofString()).toCompletableFuture().get();
            } catch (InterruptedException | ExecutionException e) {
                if(e.getCause() instanceof HttpConnectTimeoutException){
                    Core.logger.warn(String.format(
                            "request to %s timed out\n", host
                    ));
                }else e.printStackTrace();
            }

        });

    }

}
