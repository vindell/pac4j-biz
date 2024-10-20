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
import org.pac4j.core.ext.Pac4jExtConstants;
import org.pac4j.core.ext.credentials.SignatureCredentials;
import org.pac4j.core.ext.credentials.authenticator.SignatureAuthenticator;
import org.pac4j.core.ext.credentials.extractor.SignatureParameterExtractor;
import org.pac4j.core.ext.profile.Signature;
import org.pac4j.core.ext.profile.SignatureProfile;
import org.pac4j.core.ext.profile.creator.SignatureProfileCreator;
import org.pac4j.core.profile.creator.ProfileCreator;
import org.pac4j.core.util.CommonHelper;

import java.nio.charset.StandardCharsets;

public abstract class SignatureClient<C extends SignatureCredentials, P extends SignatureProfile, T extends Signature>
		extends DirectClient {
	
	private String signatureParamName = Pac4jExtConstants.SIGNATURE_PARAM;
	
	private boolean supportGetRequest = true;

	private boolean supportPostRequest;

	private String charset = StandardCharsets.UTF_8.name();
    
	/** 
	 * The location of the client login URL, i.e. https://localhost:8080/myapp/login 
	 */
	private String loginUrl;
	
	public SignatureClient() {
	}
	
	public SignatureClient(final String signatureParamName,
			final SignatureAuthenticator<C, P, T> tokenAuthenticator) {
		this.signatureParamName = signatureParamName;
		this.setAuthenticator(tokenAuthenticator);
	}

	public SignatureClient(final String signatureParamName,
			final SignatureAuthenticator<C, P, T> tokenAuthenticator, final ProfileCreator profileCreator) {
		this.signatureParamName = signatureParamName;
		this.setAuthenticator(tokenAuthenticator);
		this.setProfileCreator(profileCreator);
	}

	@Override
	protected void internalInit(final boolean forceReinit) {
		this.setProfileCreator(new SignatureProfileCreator());
		this.setCredentialsExtractor(new SignatureParameterExtractor(
				this.getSignatureParamName(), this.isSupportGetRequest(),
				this.isSupportPostRequest(), this.getCharset()));
		// ensures components have been properly initialized
        CommonHelper.assertNotNull("credentialsExtractor", getCredentialsExtractor());
        CommonHelper.assertNotNull("authenticator", getAuthenticator());
        CommonHelper.assertNotNull("profileCreator", getProfileCreator());
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

	public String getCharset() {
		return charset;
	}

	public void setCharset(String charset) {
		this.charset = charset;
	}

	public String getSignatureParamName() {
		return signatureParamName;
	}
	
	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}
	
	public String getLoginUrl() {
		return loginUrl;
	}

}
