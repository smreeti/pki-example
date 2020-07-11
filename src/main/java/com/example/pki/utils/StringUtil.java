package com.example.pki.utils;

import org.apache.commons.lang3.StringUtils;

/**
 * @author smriti on 2019-08-27
 */
public class StringUtil {

    public static String splitByCharacterTypeCamelCase(String name) {
        return StringUtils.join(StringUtils.splitByCharacterTypeCamelCase
                (name.replaceAll("\\d+", "")), " ");
    }
}
