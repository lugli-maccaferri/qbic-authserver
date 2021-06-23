package com.github.luglimaccaferri.qbic.http.controllers;

import com.github.luglimaccaferri.qbic.Core;
import com.github.luglimaccaferri.qbic.http.models.Ok;
import spark.Route;

public class NodesController {

    public static Route index = (req, res) -> {

        return new Ok().put("nodes", Core.getConfig().get("nodes").getAsJsonArray()).toResponse(res);

    };

}
