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
package org.pac4j.core.ext.credentials;

import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.pac4j.core.ext.Pac4jExtConstants;
import org.pac4j.core.ext.utils.MyCommonHelper;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.core.util.Pac4jConstants;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("serial")
public class UsernamePasswordCaptchaCredentials extends Credentials {

    private String username;

    private String password;
    
    private String captcha;

    public UsernamePasswordCaptchaCredentials(final String username, final String password) {
        this.username = username;
        this.password = password;
    }
    
    public UsernamePasswordCaptchaCredentials(final String username, final String password, String captcha) {
        this.username = username;
        this.password = password;
        this.captcha = captcha;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public String getCaptcha() {
		return captcha;
	}

	@Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        final UsernamePasswordCredentials that = (UsernamePasswordCredentials) o;

        if (username != null ? !username.equals(that.getUsername()) : that.getUsername() != null) {
            return false;
        }
        return !(password != null ? !password.equals(that.getPassword()) : that.getPassword() != null);
    }
    
    @Override
    public int hashCode() {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (password != null ? password.hashCode() : 0);
        result = 31 * result + (captcha != null ? captcha.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return MyCommonHelper.toNiceString(this.getClass(), Pac4jConstants.USERNAME, this.username,
                Pac4jConstants.PASSWORD, "[PROTECTED]", Pac4jExtConstants.CAPTCHA, "[PROTECTED]");
    }
}
