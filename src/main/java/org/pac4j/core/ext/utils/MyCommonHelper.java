package org.pac4j.core.ext.utils;

import com.fasterxml.jackson.databind.ObjectMapper;

public class MyCommonHelper {

    /* 时间格式：HH:mm:ss */
    public static final String TIME_FORMAT = "HH:mm:ss";
    /* 短日期格式：yyyy-MM-dd */
    public static final String DATE_FORMAT = "yyyy-MM-dd";
    /* 长日期格式：yyyy-MM-dd HH:mm:ss */
    public static final String DATE_LONGFORMAT = DATE_FORMAT + " " + TIME_FORMAT;


    protected static final ObjectMapper objectMapper = new ObjectMapper()
            .setDateFormat(DateFormats.getDateFormat(DATE_LONGFORMAT));



    /**
     * Build a "nice toString" for an object.
     *
     * @param clazz class
     * @param args  arguments
     * @return a "nice toString" text
     */
    public static String toNiceString(final Class<?> clazz, final Object... args) {
        final StringBuilder sb = new StringBuilder();
        sb.append("#");
        sb.append(clazz.getSimpleName());
        sb.append("# |");
        boolean b = true;
        for (final Object arg : args) {
            if (b) {
                sb.append(" ");
                sb.append(arg);
                sb.append(":");
            } else {
                sb.append(" ");
                sb.append(arg);
                sb.append(" |");
            }
            b = !b;
        }
        return sb.toString();
    }
}
