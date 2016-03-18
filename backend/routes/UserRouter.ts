///<reference path="../../typings/main.d.ts"/>



import {UserMWs} from "../middlewares/UserMWs";
export class UserRouter{
    constructor(private app){
        this.initLogin();
    }

    private initLogin() {
        this.app.get("/api/login",
            UserMWs.inverseAuthenticate,
            UserMWs.login,
            UserMWs.renderUser
        );
    };
    
}