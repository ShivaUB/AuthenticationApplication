using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AuthenticationServer.Models
{
    public class SessionFacade
    {
        static readonly string _USERNAME = "USERNAME";
        public static string USERNAME
        {
            get
            {
                string res = null;
                if (HttpContext.Current.Session[_USERNAME] != null)
                    res = (string)HttpContext.Current.Session[_USERNAME];
                return res;
            }
            set
            {
                HttpContext.Current.Session[_USERNAME] = value;
            }
        }

        static readonly string _ID = "ID";
        public static string ID
        {
            get
            {
                string res = null;
                if (HttpContext.Current.Session[_ID] != null)
                    res = (string)HttpContext.Current.Session[_ID];
                return res;
            }
            set
            {
                HttpContext.Current.Session[_ID] = value;
            }
        }

        static readonly string _PAGEREQUESTED = "PAGEREQUESTED";
        public static string PAGEREQUESTED
        {
            get
            {
                string res = null;
                if (HttpContext.Current.Session[_PAGEREQUESTED] != null)
                    res = (string)HttpContext.Current.Session[_PAGEREQUESTED];
                return res;
            }
            set
            {
                HttpContext.Current.Session[_PAGEREQUESTED] = value;
            }
        }
    }
}