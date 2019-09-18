package com.johannesbrodwall.identity.idporten;

import org.actioncontroller.Delete;
import org.actioncontroller.Get;
import org.actioncontroller.PathParam;
import org.actioncontroller.Post;
import org.actioncontroller.Put;
import org.actioncontroller.RequestParam;
import org.actioncontroller.json.JsonBody;
import org.jsonbuddy.JsonArray;
import org.jsonbuddy.JsonObject;

import java.util.Optional;

public interface IdPortenClientsApi {

    @Get("/clients")
    @JsonBody
    JsonArray list(@RequestParam("inactive") Optional<Boolean> inactive);

    @Post("/clients")
    void create(@JsonBody JsonObject clientRequest);

    @Get("/clients/:id")
    @JsonBody
    JsonObject get(@PathParam("id") String clientId);

    @Get("/clients/:id")
    @JsonBody
    JsonObject get(
            @PathParam("id") String clientId,
            @JsonBody JsonObject clientRequest
    );

    @Delete("/clients/:id")
    void delete(@PathParam("id") String clientId);

    @Post("/clients/:id/secret")
    @JsonBody
    JsonObject updateSecret(@PathParam("id") String clientId);


    @Get("/clients/:id/jwks")
    @JsonBody
    JsonObject getJwks(@PathParam("id") String clientId);

    @Post("/clients/:id/jwks")
    @JsonBody
    void addJwks(
            @PathParam("id") String clientId,
            @JsonBody JsonObject externalResource
    );

    @Delete("/clients/:id/jwks")
    @JsonBody
    JsonObject deleteJwks(@PathParam("id") String clientId);

    @Post("/clients/:clientId/onbehalfof")
    void createOnBehalfOf(
            @PathParam("clientId") String clientId,
            @JsonBody JsonObject serviceProviderDto
    );

    @Get("/clients/:clientId/onbehalfof/:id")
    @JsonBody
    JsonObject getOnBehalfOf(
            @PathParam("clientId") String clientId,
            @PathParam("id") String id
    );

    @Put("/clients/:clientId/onbehalfof/:id")
    void updateOnBehalfOf(
            @PathParam("clientId") String clientId,
            @PathParam("id") String id,
            @JsonBody JsonObject serviceProviderDto
    );

    @Delete("/clients/:clientId/onbehalfof/:id")
    void deleteOnBehalfOf(
            @PathParam("clientId") String clientId,
            @PathParam("id") String id
    );
}
