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
package org.pac4j.core.ext.authentication;

import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.ext.Pac4jExtConstants;
import org.pac4j.core.ext.authentication.captcha.CaptchaResolver;
import org.pac4j.core.ext.credentials.UsernamePasswordCaptchaCredentials;
import org.pac4j.core.ext.exception.CaptchaIncorrectException;
import org.pac4j.core.ext.exception.CaptchaNotFoundException;
import org.pac4j.core.ext.exception.OverRetryRemindException;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.core.util.Pac4jConstants;

import java.util.Optional;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class UsernamePasswordCaptchaAuthenticator implements Authenticator {

	private boolean captchaRequired = false;
	private CaptchaResolver captchaResolver;
	private String retryTimesKeyAttribute = Pac4jExtConstants.RETRY_TIMES_KEY_ATTRIBUTE_NAME;
	/** Maximum number of retry to login . */
	private int retryTimesWhenAccessDenied = 3;
	private AuthenticatingFailureCounter failureCounter;
	
	public UsernamePasswordCaptchaAuthenticator() {
	}
	
    public UsernamePasswordCaptchaAuthenticator(AuthenticatingFailureCounter failureCounter) {
		this.failureCounter = failureCounter;
	}

	@Override
	public Optional<Credentials> validate(CallContext ctx, Credentials credentials) {
        
    	if (credentials == null) {
            throw new CredentialsException("No credential");
        }
        
    	UsernamePasswordCaptchaCredentials upcCredentials = (UsernamePasswordCaptchaCredentials) credentials;
    	
        String username = upcCredentials.getUsername();
        String password = upcCredentials.getPassword();
        if (CommonHelper.isBlank(username)) {
            throw new CredentialsException("Username cannot be blank");
        }
        if (CommonHelper.isBlank(password)) {
            throw new CredentialsException("Password cannot be blank");
        }
        
        if (CommonHelper.areNotEquals(username, password)) {
            throw new CredentialsException("Username : '" + username + "' does not match password");
        }
        
    	// The retry limit has been exceeded and a reminder is required
        if(isOverRetryRemind(ctx.webContext(), ctx.sessionStore())) {
        	throw new OverRetryRemindException("The number of login errors exceeds the maximum retry limit and a verification code is required.");
        }
        
        // 验证码必填或者错误次数超出系统限制，则要求填入验证码
 		if(isCaptchaRequired() || isOverRetryTimes(ctx.webContext(), ctx.sessionStore())) {
 			
 			if(StringUtils.isBlank(upcCredentials.getCaptcha())) {
				throw new CaptchaNotFoundException("Captcha not provided");
			}
 			
 	        // 进行验证	
	        boolean validation = captchaResolver.validCaptcha(ctx.webContext(), ctx.sessionStore(), upcCredentials.getCaptcha());
			if (!validation) {
				throw new CaptchaIncorrectException("Captcha validation failed!");
			}
			
		}
        
        final CommonProfile profile = new CommonProfile();
        profile.setId(username);
        profile.addAttribute(Pac4jConstants.USERNAME, username);
        profile.addAttribute(Pac4jExtConstants.CAPTCHA, upcCredentials.getCaptcha());
        
        credentials.setUserProfile(profile);

		return Optional.ofNullable(credentials);
    }
    
    public boolean isCaptchaRequired() {
		return captchaRequired;
	}

	public void setCaptchaRequired(boolean captchaRequired) {
		this.captchaRequired = captchaRequired;
	}

	public CaptchaResolver getCaptchaResolver() {
		return captchaResolver;
	}

	public void setCaptchaResolver(CaptchaResolver captchaResolver) {
		this.captchaResolver = captchaResolver;
	}
	public AuthenticatingFailureCounter getFailureCounter() {
		return failureCounter;
	}

	public void setFailureCounter(AuthenticatingFailureCounter failureCounter) {
		this.failureCounter = failureCounter;
	}
	
	public String getRetryTimesKeyAttribute() {
		return retryTimesKeyAttribute;
	}

	public void setRetryTimesKeyAttribute(String retryTimesKeyAttribute) {
		this.retryTimesKeyAttribute = retryTimesKeyAttribute;
	}

	public int getRetryTimesWhenAccessDenied() {
		return retryTimesWhenAccessDenied;
	}

	public void setRetryTimesWhenAccessDenied(int retryTimesWhenAccessDenied) {
		this.retryTimesWhenAccessDenied = retryTimesWhenAccessDenied;
	}
	
	protected boolean isOverRetryRemind(WebContext context, SessionStore sessionStore) {
		if (null != getFailureCounter() && getFailureCounter().get(context, sessionStore, getRetryTimesKeyAttribute()) == getRetryTimesWhenAccessDenied()) {
			return true;
		}
		return false;
	}
	
	protected boolean isOverRetryTimes(WebContext context, SessionStore sessionStore) {
		if (null != getFailureCounter() && getFailureCounter().get(context, sessionStore, getRetryTimesKeyAttribute()) >= getRetryTimesWhenAccessDenied()) {
			return true;
		}
		return false;
	}
}
