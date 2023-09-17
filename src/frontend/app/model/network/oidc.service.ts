import {Injectable} from '@angular/core';
import {NetworkService} from './network.service';

@Injectable({providedIn: 'root'})
export class OidcService {
  constructor(
      private networkService: NetworkService,
  ) {
  }

  public async login(redirectTo: string): Promise<string> {
    const query: any = {};
    query['redirectTo'] = redirectTo;
    return this.networkService.getJson<string>('/oidc/login', query);
  }
}
