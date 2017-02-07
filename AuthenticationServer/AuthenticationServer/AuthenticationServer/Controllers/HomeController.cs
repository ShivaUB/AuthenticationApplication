using AuthenticationServer.Models;
using Jose;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace AuthenticationServer.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        [AllowAnonymous]
        public ActionResult Index()
        {
            if (Request.Cookies.Count > 0 && Request.Cookies.Get("AUTH_COOKIE")!=null)
            {
                HttpCookie ck = Request.Cookies["AUTH_COOKIE"];
                string secret = ConfigurationManager.AppSettings["SECRET_KEY"];
                byte[] secretKey = Base64UrlDecode(secret);
                var payload = JWT.Decode(ck.Value, secretKey, JwsAlgorithm.HS256);
                Dictionary<string, object> res = JsonConvert.DeserializeObject<Dictionary<string, object>>(payload);
                SessionFacade.ID = res["uID"].ToString();
                SessionFacade.USERNAME = res["email"].ToString();
            }
            return View();
        }
        [AllowAnonymous]
        public ActionResult About()
        {
            ViewBag.Message = "Description about the Application goes here..";

            return View();
        }
        [AllowAnonymous]
        public ActionResult Contact()
        {
            ViewBag.Message = "Contact at : ";

            return View();
        }
        static byte[] Base64UrlDecode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default:
                    throw new System.Exception(
             "Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }
    }

}