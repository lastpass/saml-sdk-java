/*
 * AttributeSet - subject details parsed from SAML Response
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

import java.util.Map;
import java.util.List;

/**
 * AttributeSet contains the NameID from the subject as well
 * as any attributes contained in the assertion, as a
 * map of Attribute Name to list of String values.
 */
public class AttributeSet
{
    private String nameId;
    private Map<String, List<String>> attributes;

    public AttributeSet(String nameId,
                        Map<String, List<String>> attributes)
    {
        this.nameId = nameId;
        this.attributes = attributes;
    }

    public String getNameId()
    {
        return nameId;
    }

    public Map<String, List<String>> getAttributes()
    {
        return this.attributes;
    }
}
