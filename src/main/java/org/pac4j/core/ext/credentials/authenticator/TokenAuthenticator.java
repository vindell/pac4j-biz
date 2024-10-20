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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.exception.HttpCommunicationException;
import org.pac4j.core.ext.profile.Token;
import org.pac4j.core.ext.profile.TokenProfile;
import org.pac4j.core.ext.profile.TokenProfileDefinition;
import org.pac4j.core.ext.profile.definition.TokenProfileDefinitionAware;
import org.pac4j.core.ext.utils.HttpHeaders;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.core.util.HttpUtils;
import org.pac4j.core.util.HttpUtils2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public abstract class TokenAuthenticator<P extends TokenProfile, T extends Token>
	extends TokenProfileDefinitionAware<P, T>  implements Authenticator {
	
	protected final Logger logger = LoggerFactory.getLogger(getClass());
	protected final String DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0";
	protected final String DEFAULT_ACCEPT_HEADER = "application/json, text/plain, */*";
	protected final ObjectMapper objectMapper = new ObjectMapper();

	/* Map containing user defined headers */
	private Map<String, String> customHeaders = new HashMap<>();
    /* Map containing user defined parameters */
    private Map<String, String> customParams = new HashMap<>();
    
    private String charset = StandardCharsets.UTF_8.name();

	private boolean encodeParams = true;
	
	private String parameterName = "token";
	
	public TokenAuthenticator() {
	}
	
	public TokenAuthenticator(String parameterName, boolean encodeParams) {
		this.parameterName = parameterName;
        this.encodeParams = encodeParams;
	}
	
	@Override
    protected void internalInit(final boolean forceReinit) {
		CommonHelper.assertNotNull("parameterName", parameterName);
		CommonHelper.assertNotNull("profileDefinition", getProfileDefinition());
    }

	@Override
	public Optional<Credentials> validate(CallContext ctx, Credentials credentials) {
        
    	if (credentials == null) {
            throw new CredentialsException("No credential");
        }
        
    	TokenCredentials tokenCredentials = (org.pac4j.core.credentials.TokenCredentials) credentials;
        String token = tokenCredentials.getToken();
        if (CommonHelper.isBlank(token)) {
            throw new CredentialsException("Token cannot be blank");
        }
        
        final Optional<P> profile = retrieveUserProfileFromToken(ctx , tokenCredentials);
        
        logger.debug("profile: {}", profile.get());
        credentials.setUserProfile(profile.get());

		return Optional.ofNullable(credentials);
    }
	
	/**
     * Get the access token from Auth credentials.
     *
     * @param credentials credentials
     * @return the access token
     */
    protected abstract T getAccessToken(final TokenCredentials credentials);
    
    /**
     * Retrieve the user profile from the access token.
     *
     * @param ctx the call context
     * @param credentials the credentials
     * @return the user profile
     */
    protected Optional<P> retrieveUserProfileFromToken(final CallContext ctx, final TokenCredentials credentials) {
    	
    	final T accessToken = getAccessToken(credentials);
    	
    	logger.debug("accessToken: {}", accessToken.getRawResponse());
    	
    	TokenProfileDefinition<P, T> profileDefinition = getProfileDefinition();
		CommonHelper.assertNotNull("profileDefinition", profileDefinition);
			
		final String profileUrl = profileDefinition.getProfileUrl(ctx.webContext(), accessToken);
		
        final String body = retrieveUserProfileFromRestApi(ctx.webContext(), accessToken, profileUrl);
        logger.debug("body: {}", body);
        if (body == null) {
            throw new HttpCommunicationException("No data found for accessToken: " + accessToken);
        }        
        final P profile = (P) profileDefinition.extractUserProfile(body);
        logger.debug("Authentication success for token: {}", accessToken.getRawResponse());
        return Optional.of(profile);
    }
    
    /**
     * Return the body from the REST API, passing the token auth.
     * To be overridden using another HTTP client if necessary.
     *
    * @param context the web context
     * @param accessToken the access token
     * @param profileUrl  url of the data
     * @return the response body
     */
    protected String retrieveUserProfileFromRestApi(final WebContext context, final T accessToken, final String profileUrl) {
    	
    	logger.debug("accessToken: {} / profileUrl: {}", accessToken.getRawResponse(), profileUrl);
        final long t0 = System.currentTimeMillis();
         
        HttpURLConnection connection = null;
        try {
        	
        	Map<String, String> finalHeaders = this.finalHeaders(context, accessToken, profileUrl, getCustomHeaders());
       	 	logger.debug("finalHeaders: {} ", objectMapper.writeValueAsString(finalHeaders));
        	
       	 	Map<String, String> finalParams = this.finalParams(context, accessToken, profileUrl, getCustomParams());
            logger.debug("finalParams: {} ", objectMapper.writeValueAsString(finalParams));
             
			connection = HttpUtils2.openGetConnection(profileUrl, finalHeaders, finalParams);
            
            int code = connection.getResponseCode();
            final long t1 = System.currentTimeMillis();
            logger.debug("Request took: " + (t1 - t0) + " ms for: " + profileUrl);
            if (code == 200) {
                return HttpUtils.readBody(connection);
            } else if (code == 401 || code == 403) {
                logger.info("Authentication failure for token: {} -> {}", accessToken.getRawResponse(), HttpUtils.buildHttpErrorMessage(connection));
                return null;
            } else {
                logger.warn("Unexpected error for token: {} -> {}", accessToken.getRawResponse(), HttpUtils.buildHttpErrorMessage(connection));
                return null;
            }
        } catch (final IOException e) {
        	throw new HttpCommunicationException("Error getting body: " + e.getMessage());
        } finally {
            HttpUtils.closeConnection(connection);
        }
    }

    protected Map<String, String> finalHeaders(final WebContext context,final T token, final String url, final Map<String, String> headers ) {
    	
    	 final Map<String,String> finalHeaders = new HashMap<>();
    	 finalHeaders.putAll(headers);
    	 
         /* 
  		 * 配置本次连接的Content-type，配置为application/x-www-form-urlencoded的 意思是正文是urlencoded编码过的form参数，下面我们可以看到我们对正文内容使用URLEncoder.encode进行编码
  		 */	
         if(!headers.containsKey(HttpConstants.CONTENT_TYPE_HEADER)) {
        	 headers.put( HttpConstants.CONTENT_TYPE_HEADER, HttpConstants.APPLICATION_FORM_ENCODED_HEADER_VALUE);
         }
         // 设置通用的请求属性 (模拟浏览器请求头) 
         if(!headers.containsKey(HttpConstants.ACCEPT_HEADER)) {
        	 headers.put( HttpConstants.ACCEPT_HEADER, context.getRequestHeader(HttpConstants.ACCEPT_HEADER).orElse(DEFAULT_ACCEPT_HEADER)); 
         }
         if(!headers.containsKey(HttpHeaders.USER_AGENT)) {
        	 headers.put(HttpHeaders.USER_AGENT, context.getRequestHeader(HttpHeaders.USER_AGENT).orElse(DEFAULT_USER_AGENT));
         }
         
         return finalHeaders;
         
    }
    
    protected Map<String, String> finalParams(final WebContext context,final T token, final String url, final Map<String,String> params) {
    	
        final Map<String,String> finalParams = new HashMap<>();
        finalParams.putAll(params);
        
        if(this.isEncodeParams()) {
       	// 对自定义参数进行转码
            for (String paramName : finalParams.keySet()) {
           	 try {
           		 finalParams.put(paramName, URLEncoder.encode(params.get(paramName), getCharset()));
   			} catch (UnsupportedEncodingException e) {
   			}
   		 }
        }
        
        finalParams.put(getParameterName(), token.getRawResponse());
        
        return finalParams;
        
   }

	public Map<String, String> getCustomHeaders() {
		return customHeaders;
	}

	public void setCustomHeaders(Map<String, String> customHeaders) {
		this.customHeaders = customHeaders;
	}

	public Map<String, String> getCustomParams() {
		return customParams;
	}

	public void setCustomParams(Map<String, String> customParams) {
		this.customParams = customParams;
	}

	public String getParameterName() {
		return parameterName;
	}

	public void setParameterName(String parameterName) {
		this.parameterName = parameterName;
	}

	public String getCharset() {
		return charset;
	}

	public void setCharset(String charset) {
		this.charset = charset;
	}

	public boolean isEncodeParams() {
		return encodeParams;
	}

	public void setEncodeParams(boolean encodeParams) {
		this.encodeParams = encodeParams;
	}
	
}
