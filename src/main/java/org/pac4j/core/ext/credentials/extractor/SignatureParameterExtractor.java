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
package org.pac4j.core.ext.credentials.extractor;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.WebContextHelper;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.extractor.CredentialsExtractor;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.ext.Pac4jExtConstants;
import org.pac4j.core.ext.credentials.SignatureCredentials;
import org.pac4j.core.ext.utils.MyCommonHelper;
import org.pac4j.core.util.CommonHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureParameterExtractor implements CredentialsExtractor {

	protected final Logger logger = LoggerFactory.getLogger(getClass());
	
	private String signatureParamName = Pac4jExtConstants.SIGNATURE_PARAM;
	
    private boolean supportGetRequest = true;

    private boolean supportPostRequest;
    
    private String charset = StandardCharsets.UTF_8.name();
    
	public SignatureParameterExtractor(String signatureParamName) {
		this(signatureParamName, false, true, StandardCharsets.UTF_8.name());
	}
	
	public SignatureParameterExtractor(String signatureParamName, String charset) {
		this(signatureParamName, false, true, charset);
	}
	
	public SignatureParameterExtractor(String signatureParamName, boolean supportGetRequest,
			boolean supportPostRequest, String charset) {
		this.signatureParamName = signatureParamName;
        this.supportGetRequest = supportGetRequest;
        this.supportPostRequest = supportPostRequest;
        this.charset = charset;
	}

	@Override
	public Optional<Credentials> extract(CallContext ctx) {

		WebContext context = ctx.webContext();
		logger.debug("supportGetRequest: {}", this.supportGetRequest);
		logger.debug("supportPostRequest: {}", this.supportPostRequest);
		
		if (WebContextHelper.isGet(context) && !supportGetRequest) {
            throw new CredentialsException("GET requests not supported");
        } else if (WebContextHelper.isPost(context) && !supportPostRequest) {
            throw new CredentialsException("POST requests not supported");
        }
        
        logger.debug("signatureParamName: {}", this.signatureParamName);
        
        String paylod = context.getRequestContent();
        Optional<String> signature = context.getRequestParameter(this.signatureParamName);
        if ( StringUtils.isEmpty(paylod) || !signature.isPresent()) {
    		return Optional.empty();
        }
        
    	logger.debug("paylod : {}", paylod);
    	logger.debug("signature : {}", signature.get());
    	return Optional.of(new SignatureCredentials(paylod, signature.get()));
    }
	
	@Override
    public String toString() {
        return MyCommonHelper.toNiceString(this.getClass(), "signatureParamName", signatureParamName,
        		 "supportGetRequest", supportGetRequest, "supportPostRequest", supportPostRequest, "charset", charset);
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

	public void setSignatureParamName(String signatureParamName) {
		this.signatureParamName = signatureParamName;
	}

}
