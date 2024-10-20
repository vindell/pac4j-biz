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
import org.pac4j.core.ext.utils.MyCommonHelper;
import org.pac4j.core.util.CommonHelper;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@SuppressWarnings("serial")
public class SignatureCredentials extends Credentials {

	private final String payload;
    private final String signature;

    public SignatureCredentials(String payload, String signature) {
        this.payload = payload;
        this.signature = signature;
    }

    public String getPayload() {
		return payload;
	}

	public String getSignature() {
		return signature;
	}

	@Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        final SignatureCredentials that = (SignatureCredentials) o;

        return !(signature != null ? !signature.equals(that.signature) : that.signature != null);
    }

    @Override
    public int hashCode() {
        return signature != null ? signature.hashCode() : 0;
    }

    @Override
    public String toString() {
        return MyCommonHelper.toNiceString(this.getClass(), "payload", this.payload, "signature", this.signature);
    }
    
}
