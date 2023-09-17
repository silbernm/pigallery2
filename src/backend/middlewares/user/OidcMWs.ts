import { NextFunction, Request, Response } from 'express';
import { ErrorCodes, ErrorDTO } from '../../../common/entities/Error';
import { Config } from '../../../common/config/private/Config';
import { Issuer, BaseClient, generators } from 'openid-client';
import { Logger } from '../../Logger';
import { UserDTO, UserRoles } from '../../../common/entities/UserDTO';
import { Utils } from '../../../common/Utils';
import { ObjectManagers } from '../../model/ObjectManagers';

const LOG_TAG = '[Oidc]';
const OIDC_NONCE_SESSION_VARIABLE = 'oidc_nonce';
const OIDC_REDIRECT_TO_SESSION_VARIABLE = 'oidc_redirect_to';
const CLIENT_RETRY_MILLISECONDS = 60 * 1000;
const CLIENT_REFRESH_MILLISECONDS = 60 * 60 * 1000;

export class OidcMWs {
    private static readonly redirectUri = Config.Server.publicUrl + Config.Server.apiPath + '/oidc/cb';

    private static lastSuccessfulInit?: Date;
    private static lastStartedInit?: Date;
    private static client?: BaseClient = null;

    public static async startOidcLoginProcess(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const client = await OidcMWs.getClient();
            const nonce = generators.nonce();
            req.session[OIDC_NONCE_SESSION_VARIABLE] = nonce;

            req.resultPipe = client.authorizationUrl({
                scope: 'openid email profile roles',
                response_mode: 'form_post',
                nonce
            });

            OidcMWs.storeRedirectTo(req, req.query['redirectTo'])
            next();
        } catch (err) {
            return next(
                new ErrorDTO(
                    ErrorCodes.OIDC_ERROR,
                    'Error during starting OIDC login process',
                    err
                )
            );
        }
    }

    public static async oidcCallback(req: Request, res: Response, next: NextFunction): Promise<void> {
        try {
            const client = await OidcMWs.getClient();
            Logger.debug(LOG_TAG, "Received OIDC callback, fetching and validating id_token...");
            const params = client.callbackParams(req);
            const nonce = req.session[OIDC_NONCE_SESSION_VARIABLE];
            const tokenSet = await client.callback(OidcMWs.redirectUri, params, { nonce });
            req.session['user'] = await OidcMWs.getUserFromClaims(tokenSet.claims())

            res.redirect(OidcMWs.getRedirectTo(req))
            next()
        } catch (err) {
            return next(
                new ErrorDTO(
                    ErrorCodes.OIDC_ERROR,
                    'Error during finishing OIDC login process',
                    err
                )
            );
        }
    }

    private static async getUserFromClaims(claims: any): Promise<UserDTO> {
        Logger.debug(LOG_TAG, `Received and verified OIDC claims ${JSON.stringify(claims)}`);
        const username = claims[Config.Users.Oidc.userNameClaim];
        if (typeof username != "string" || username.length == 0) {
            throw new Error("Received no username from identity provider");
        }

        const user = Utils.clone(
            await ObjectManagers.getInstance().UserManager.findOne({name: username}));
        if(user) {
            Logger.info(LOG_TAG, `OIDC login complete for existing user ${username}`);
            return user;
        }
        if(!Config.Users.Oidc.allowNewUsers) {
            throw new Error(`OIDC login failed for unknown user ${username}`)
        }

        var role = Config.Users.Oidc.defaultRole;
        if(Config.Users.Oidc.useOidcRole) {
            var mappedRole = OidcMWs.getRoleFromClaims(claims);
            role = mappedRole || role;
        }
        Logger.info(LOG_TAG, `OIDC login complete for user ${username}, role ${role}`);
        return {
            name: username,
            role: role,
            permissions: []
        } as UserDTO;
    }

    private static getRoleFromClaims(claims: any): UserRoles {
        const roles = OidcMWs.parseRoleClaim(claims)
        if (OidcMWs.isRoleMatching(roles, Config.Users.Oidc.roleMapping.developerRoleRegex)) {
            return UserRoles.Developer;
        }
        if (OidcMWs.isRoleMatching(roles, Config.Users.Oidc.roleMapping.adminRoleRegex)) {
            return UserRoles.Admin;
        }
        if (OidcMWs.isRoleMatching(roles, Config.Users.Oidc.roleMapping.userRoleRegex)) {
            return UserRoles.User;
        }
        if (OidcMWs.isRoleMatching(roles, Config.Users.Oidc.roleMapping.guestRoleRegex)) {
            return UserRoles.Guest;
        }
        if (OidcMWs.isRoleMatching(roles, Config.Users.Oidc.roleMapping.limitedGuestRoleRegex)) {
            return UserRoles.LimitedGuest;
        }
        return null;
    }

    private static parseRoleClaim(claims: any): string[] {
        const roleClaim = claims[Config.Users.Oidc.roleClaim];
        if (!roleClaim) {
            return [];
        }
        if (typeof roleClaim == 'string') {
            return [roleClaim]
        } else {
            return roleClaim;
        }
    }

    private static isRoleMatching(roles: string[], roleRegex: string) {
        const regexp = new RegExp(`^${roleRegex}$`)
        for (const role of roles) {
            if (regexp.test(role)) {
                return true;
            }
        }
    }

    private static storeRedirectTo(req: Request, userRedirectToParam: any) {
        const isRelativePath = typeof userRedirectToParam == 'string' && userRedirectToParam.startsWith("/");
        if (isRelativePath) {
            req.session[OIDC_REDIRECT_TO_SESSION_VARIABLE] = userRedirectToParam;
        } else {
            req.session[OIDC_REDIRECT_TO_SESSION_VARIABLE] = "";
        }
    }

    private static getRedirectTo(req: Request): string {
        return Config.Server.publicUrl + (req.session[OIDC_REDIRECT_TO_SESSION_VARIABLE] || "")
    }

    private static async getClient(): Promise<BaseClient> {
        // Usage of lastStartedInit is also important to prevent concurrent client creations
        const isFirstInitialization = OidcMWs.lastStartedInit == null;
        const shouldRetryClient = OidcMWs.hasTimePassed(OidcMWs.lastStartedInit, CLIENT_RETRY_MILLISECONDS);
        const shouldRefreshClient = OidcMWs.hasTimePassed(OidcMWs.lastSuccessfulInit, CLIENT_REFRESH_MILLISECONDS);

        if (isFirstInitialization || shouldRetryClient || shouldRefreshClient) {
            OidcMWs.lastStartedInit = new Date()
            const newClient = await OidcMWs.tryCreateClient();
            if (newClient != null) {
                OidcMWs.lastSuccessfulInit = new Date()
                OidcMWs.client = newClient;
            }
        }
        if (OidcMWs.client == null) {
            throw new Error("Could not discover client")
        }
        return OidcMWs.client;
    }

    private static hasTimePassed(time: Date, milliseconds: number): boolean {
        return time != null && new Date().getTime() - time.getTime() >= milliseconds;
    }

    private static async tryCreateClient(): Promise<BaseClient> {
        try {
            Logger.verbose(LOG_TAG, 'Discovering OIDC issuer...');
            const issuer = await Issuer.discover(Config.Users.Oidc.issuerUrl)
            Logger.verbose(LOG_TAG, 'Successfully discovered OIDC issuer');

            return new issuer.Client({
                client_id: Config.Users.Oidc.clientId,
                client_secret: Config.Users.Oidc.clientSecret || null,
                redirect_uris: [OidcMWs.redirectUri],
                response_types: ['id_token'],
                // id_token_signed_response_alg (default "RS256")
            });
        } catch (error) {
            Logger.error(LOG_TAG, 'Failed to discover OIDC issuer', error);
        }
    }
}
