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
package org.pac4j.core.ext.credentials.authenticator;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.ext.credentials.SignatureCredentials;
import org.pac4j.core.ext.profile.Signature;
import org.pac4j.core.ext.profile.SignatureProfile;
import org.pac4j.core.ext.profile.definition.SignatureProfileDefinitionAware;
import org.pac4j.core.util.CommonHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public abstract class SignatureAuthenticator<C extends SignatureCredentials, P extends SignatureProfile, T extends Signature>
	extends SignatureProfileDefinitionAware<P, T>  implements Authenticator {
	
	protected final Logger logger = LoggerFactory.getLogger(getClass());
    private String charset = StandardCharsets.UTF_8.name();
	
	public SignatureAuthenticator() {
	}
	
	@Override
    protected void internalInit(final boolean forceReinit) {
		CommonHelper.assertNotNull("profileDefinition", getProfileDefinition());
    }

	@Override
	public Optional<Credentials> validate(CallContext ctx, Credentials credentials) {

    	if (credentials == null) {
            throw new CredentialsException("No credential");
        }
        
    	SignatureCredentials signatureCredentials = (SignatureCredentials) credentials;
        String payload = signatureCredentials.getPayload();
        if (CommonHelper.isBlank(payload)) {
            throw new CredentialsException("Payload cannot be blank");
        }

        final Optional<P> profile = Optional.of(getProfileDefinition().extractUserProfile(payload, signatureCredentials.getSignature()));
        
        logger.debug("profile: {}", profile.get());
        credentials.setUserProfile(profile.get());

		return Optional.ofNullable(credentials);
    }

	public String getCharset() {
		return charset;
	}

	public void setCharset(String charset) {
		this.charset = charset;
	}
	
}
