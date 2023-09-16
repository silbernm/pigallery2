import {Injectable} from '@angular/core';
import {NetworkService} from './network.service';

@Injectable({providedIn: 'root'})
export class OidcService {
  constructor(
      private networkService: NetworkService,
  ) {
  }

  public async getOidcConfigurations(): Promise<string[]> {
    return this.networkService.getJson<string[]>('/oidc/configs');
  }

  public async login(oidcConfiguration: string, redirectTo: Location): Promise<void> {
    const query: any = {};
    query['configuration'] = oidcConfiguration;
    query['redirectTo'] = redirectTo;
    const authenticationUrl = await this.networkService.getJson<Location>('/oidc/login', query);
    window.location = authenticationUrl;
  }
}
