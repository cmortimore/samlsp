package com.salesforce.util;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

public class XSDDateTime {

    private int moreMinutes;

    public XSDDateTime() {
        moreMinutes = 0;
    }

    public XSDDateTime(int moreMinutes) {
        this.moreMinutes = moreMinutes;
    }

    public String getDateTime() {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("GMT"));
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MINUTE, moreMinutes);	//Adding 1 day to current date
        return df.format(cal.getTime()) + "Z";
    }


}
