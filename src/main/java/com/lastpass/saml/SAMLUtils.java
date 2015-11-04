/*
 * SAMLUtils - Utility functions
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * Copyright (c) 2014 LastPass, Inc.
 */
package com.lastpass.saml;

import java.security.SecureRandom;

public class SAMLUtils
{
    private static final char[] hexes = "0123456789abcdef".toCharArray();
    private static String hexEncode(byte[] b)
    {
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++)
        {
            out[i*2] = hexes[(b[i] >> 4) & 0xf];
            out[i*2 + 1] = hexes[b[i] & 0xf];
        }
        return new String(out);
    }

    /**
     *  Generate a request ID suitable for passing to
     *  SAMLClient.createAuthnRequest.
     */
    public static String generateRequestId()
    {
        /* compute a random 256-bit string and hex-encode it */
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[32];
        sr.nextBytes(bytes);
        return hexEncode(bytes);
    }
}
