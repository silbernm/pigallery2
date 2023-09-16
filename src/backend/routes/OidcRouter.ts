import {Express,urlencoded} from 'express';
import * as _csrf from 'csurf';
import {Config} from '../../common/config/private/Config';
import {ServerTimingMWs} from '../middlewares/ServerTimingMWs';
import {OidcMWs} from '../middlewares/user/OidcMWs';
import { RenderingMWs } from '../middlewares/RenderingMWs';

export class OidcRouter {
  public static route(app: Express): void {
    this.oidcConfigs(app);
    this.oidcLogin(app);
    this.oidcCallback(app);
  }

  protected static oidcConfigs(app: Express): void {
    app.get(
        [Config.Server.apiPath + '/oidc/configs'],
        OidcMWs.getOidcConfigurations,
        ServerTimingMWs.addServerTiming,
        RenderingMWs.renderResult
    );
  }

  protected static oidcLogin(app: Express): void {
    app.get(
        [Config.Server.apiPath + '/oidc/login'],
        OidcMWs.startOidcLoginProcess,
        ServerTimingMWs.addServerTiming,
        RenderingMWs.renderResult
    );
  }

  protected static oidcCallback(app: Express): void {
    app.post(
        [Config.Server.apiPath + '/oidc/cb'],
        urlencoded({ extended: true }),
        OidcMWs.oidcCallback,
        ServerTimingMWs.addServerTiming,
        RenderingMWs.renderResult
    );
  }
}
