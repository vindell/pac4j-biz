/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.pac4j.core.ext.client;

import org.pac4j.core.client.DirectClient;
import org.pac4j.core.ext.credentials.authenticator.TokenAuthenticator;
import org.pac4j.core.ext.credentials.extractor.TokenParameterExtractor;
import org.pac4j.core.ext.profile.Token;
import org.pac4j.core.ext.profile.TokenProfile;
import org.pac4j.core.ext.profile.creator.TokenProfileCreator;
import org.pac4j.core.profile.creator.ProfileCreator;
import org.pac4j.core.util.CommonHelper;

public abstract class TokenClient<P extends TokenProfile, T extends Token> extends DirectClient {

	private String parameterName = "";
	
	private boolean supportGetRequest = false;
	
	private boolean supportPostRequest = true;
	/** 
	 * The location of the client login URL, i.e. https://localhost:8080/myapp/login 
	 */
	private String loginUrl;
	
	public TokenClient() {
	}

	public TokenClient(final String parameterName, final TokenAuthenticator<P, T> tokenAuthenticator) {
		this.parameterName = parameterName;
		this.setAuthenticator(tokenAuthenticator);
	}

    public TokenClient(final String parameterName,
                           final TokenAuthenticator<P, T> tokenAuthenticator,
                           final ProfileCreator profileCreator) {
        this.parameterName = parameterName;
		this.setAuthenticator(tokenAuthenticator);
		this.setProfileCreator(profileCreator);
    }
	
	@Override
	protected void internalInit(final boolean forceReinit) {
		this.setProfileCreator(new TokenProfileCreator());
		this.setCredentialsExtractor(new TokenParameterExtractor(this.getParameterName(), this.isSupportGetRequest(), this.isSupportPostRequest()));
		
		// ensures components have been properly initialized
        CommonHelper.assertNotNull("credentialsExtractor", getCredentialsExtractor());
        CommonHelper.assertNotNull("authenticator", getAuthenticator());
        CommonHelper.assertNotNull("profileCreator", getProfileCreator());
	}
	
	public String getParameterName() {
		return parameterName;
	}

	public void setParameterName(String parameterName) {
		this.parameterName = parameterName;
	}

	public boolean isSupportGetRequest() {
		return supportGetRequest;
	}

	public void setSupportGetRequest(boolean supportGetRequest) {
		this.supportGetRequest = supportGetRequest;
	}

	public boolean isSupportPostRequest() {
		return supportPostRequest;
	}

	public void setSupportPostRequest(boolean supportPostRequest) {
		this.supportPostRequest = supportPostRequest;
	}
	
	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}
	
	public String getLoginUrl() {
		return loginUrl;
	}
}
