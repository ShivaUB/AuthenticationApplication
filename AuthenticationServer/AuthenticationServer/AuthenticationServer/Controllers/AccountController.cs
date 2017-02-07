using AuthenticationServer.Models;
using AuthenticationServer.Models.AuthenticationModels;
using AuthenticationServer.Models.DataLayerModels;
using Jose;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.UI;
using Twilio;

namespace AuthenticationServer.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        string secret = ConfigurationManager.AppSettings["SECRET_KEY"];
        static string SentCode = "";
        static string PhoneNo = "";
        [AllowAnonymous]
        public ActionResult Register()
        {
            if (SessionFacade.USERNAME == null)
            {
                RegisterUserModel rum = new RegisterUserModel();
                return View(rum);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterUserModel rum)
        {
            User ur = new User();
            if (ModelState.IsValid && (rum.Password.Where(Char.IsDigit).Count() > 0 && rum.Password.Where(Char.IsUpper).Count() > 0))
            {
                ur.Email = rum.Email;
                ur.PasswordHash = GetHashString(rum.Password);
                ur.Id = GetHashString(ur.Email + "-" + ur.PasswordHash + "-" + DateTime.Now.ToString()).Substring(0, 25);
                ur.SecurityStamp = GetHashString(rum.Password + "-" + ur.PasswordHash).Substring(0, 15);
                ur.UserName = "0";
                using (var db = new AuthDBEntities())
                {
                    db.Users.Add(ur);
                    db.SaveChanges();
                }
                return Login(new LoginModel { Email=rum.Email,Password=rum.ConfirmPassword,RememberMe=false});
            }
            if(!(rum.Password.Where(Char.IsDigit).Count() > 0 && rum.Password.Where(Char.IsUpper).Count() > 0))
            {
                ModelState.AddModelError(string.Empty, "The Password must contain atleast 1 UpperCase Letter and 1 Numeric");
            }
            return View("Register",rum);
        }

        /// <summary>
        /// Sends LoginModel Object to LoginView
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]
        public ActionResult Login()
        {
            if (SessionFacade.USERNAME == null)
            {
                LoginModel lm = new LoginModel();
                return View(lm);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginModel lm)
        {
            //Check the code
                User usr = null;
                using (var db = new AuthDBEntities())
                {
                    string pswd = GetHashString(lm.Password);
                    usr = db.Users.Where(p => p.Email == lm.Email && p.PasswordHash == pswd).FirstOrDefault<User>();
                if (usr.TwoFactorEnabled == true)
                {
                    SentCode = GetHashString(lm.Email + DateTime.Now.ToString()).Substring(0, 5);
                  //  SendConfirmationCode(SentCode, GetUserbyUName(lm.Email).PhoneNumber);
                    ViewData["Login"] = lm;
                    return TwoFactorAuth();
                }
                }
            return PerformLogin(usr);
        }

        [AllowAnonymous]
        public ActionResult TwoFactorAuth()
        {
            TwoStepLogin tsl = new TwoStepLogin();
            return View("TwoFactorAuth", tsl);
        }

        [HttpPost]
        [AllowAnonymous]
        public ActionResult TwoFactorAuth(TwoStepLogin tsl)
        {
            if (SentCode == tsl.VerificationCode)
            {
                using(var db = new AuthDBEntities())
                {
                    return PerformLogin(db.Users.Where(p => p.Email == tsl.Email).SingleOrDefault());
                }
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        public ActionResult PerformLogin(User usr)
        {
            if (usr != null)
            {
                SessionFacade.USERNAME = usr.Email;
                SessionFacade.ID = usr.Id;
                SendCookie();
                if (SessionFacade.PAGEREQUESTED != null)
                {
                    string[] addr = SessionFacade.PAGEREQUESTED.Split('/');
                    return RedirectToAction(addr[2], addr[1]);
                }
                return View("LoggedInView", usr);
            }
            else
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return View();
            }
        }

        [AllowAnonymous]
        public ActionResult Loggedin()
        {
            return View("LoggedInView", GetUserbyUName(SessionFacade.USERNAME));
        }

        [AllowAnonymous]
        public ActionResult ManageLogins()
        {
            return View("ManageLogins");
        }

        [AllowAnonymous]
        public ActionResult RemovePhoneNumber(AddPhoneModel apm)
        {
            string pno = apm.Ph_No;
            using (var db = new AuthDBEntities())
            {
                var usr = db.Users.Where(p => p.UserName == SessionFacade.USERNAME && p.Id == SessionFacade.ID).SingleOrDefault();
                usr.TwoFactorEnabled = false;
                usr.PhoneNumber = null;
                usr.PhoneNumberConfirmed = false;
                db.SaveChanges();
            }
            return View("LoggedInView", GetUserbyUName(SessionFacade.USERNAME));
        }


        [AllowAnonymous]
        public ActionResult AddPhoneNumber()
        {
            AddPhoneModel apm = new AddPhoneModel();
            return View("AddPhoneNumber", apm);
        }

        
        [AllowAnonymous]
        public ActionResult ManageTwoStep()
        {
            User usr = null;
             using (var db = new AuthDBEntities())
            {
                usr = db.Users.Where(p => p.UserName == SessionFacade.USERNAME && p.Id == SessionFacade.ID).SingleOrDefault();
                if(usr.TwoFactorEnabled == false && usr.PhoneNumberConfirmed==true)
                {
                    usr.TwoFactorEnabled = true;
                }
                else
                {
                    usr.TwoFactorEnabled = false;
                }
                db.SaveChanges();
            }
            return View("LoggedInView", usr);
        }

        void SendConfirmationCode(string code,string PhoneNo)
        {
            string ACCOUNT_SID = ConfigurationManager.AppSettings["ACCOUNT_SID"];
            string AUTH_TOKEN = ConfigurationManager.AppSettings["AUTH_TOKEN"];
            string FROM_PH_NO = ConfigurationManager.AppSettings["FROM_PH_NO"];
            TwilioRestClient client = new TwilioRestClient(ACCOUNT_SID, AUTH_TOKEN);

            client.SendMessage(FROM_PH_NO, PhoneNo, "Your Verification Code for Authentication Server : \n" + SentCode);
        }

        [HttpPost]
        [AllowAnonymous]
        public ActionResult AddPhoneNumber(AddPhoneModel apm)
        {
            VerifyPhoneNumber vpn = new VerifyPhoneNumber();
            PhoneNo = apm.Confirm_Ph_No;
            SentCode = GetHashString(apm.Confirm_Ph_No).Substring(0, 5);
            SendConfirmationCode(SentCode, PhoneNo);
            return View("VerifyPhoneNumberView", vpn);
        }

        [AllowAnonymous]
        public ActionResult VerifyPhoneNumber(VerifyPhoneNumber vpn)
        {
            if(SentCode == vpn.ConfirmCode)
            {
                ModelState.AddModelError("", "Phone Number Verified Successfully..!!!");
            }
            else
            {
                ModelState.AddModelError("", "Invalid Code :-(");
            }
            using(var db = new AuthDBEntities())
            {
                User u = db.Users.Where(p => p.UserName == SessionFacade.USERNAME).SingleOrDefault();
                u.PhoneNumber = PhoneNo;
                u.PhoneNumberConfirmed = true;
                db.SaveChanges();
            }
            return View("LoggedInView", GetUserbyUName(SessionFacade.USERNAME));
        }

       [AllowAnonymous]
        public ActionResult ChangePassword()
        {
            if (SessionFacade.USERNAME != null)
            {
                ChangePasswordModel cpm = new ChangePasswordModel();
                return View("ChangePasswordView", cpm);
            }
            else
            {
                SessionFacade.PAGEREQUESTED = Request.ServerVariables["SCRIPT_NAME"];
                return RedirectToAction("Login");
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ChangePassword(ChangePasswordModel cpm)
        {
                User usr = null;
                using (var db = new AuthDBEntities())
                {
                    string hashedOldPassword = GetHashString(cpm.OldPassword);
                    usr = db.Users.Where(p => p.PasswordHash == hashedOldPassword && p.Id == SessionFacade.ID).FirstOrDefault();
                    if (usr != null)
                    {
                        usr.PasswordHash = GetHashString(cpm.ConfirmPassword);
                        db.SaveChanges();
                        ModelState.AddModelError(string.Empty, " Your Password Changed Successfully..!!! ");
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, " Your Old Password is Incorrect :-( ");
                    }
                }
            return View("ChangePasswordView");
        }

        [AllowAnonymous]
        public ActionResult Logoff()
        {
            HttpCookie ck = Request.Cookies.Get("AUTH_COOKIE");
            ck.Expires=DateTime.Now.AddDays(-1);
            Response.Cookies.Add(ck);
            SessionFacade.USERNAME = null;
            SessionFacade.ID = null;
            return RedirectToAction("Index", "Home");
        }

        private void SendCookie()
        {
            string token = create_JWT_Token();
            HttpCookie ck=new HttpCookie("AUTH_COOKIE");
            ck.Value = token;
            ck.Expires = DateTime.Now.AddDays(1);
            Response.Cookies.Add(ck);
        }

        private string create_JWT_Token()
        {
            byte[] secretKey = Base64UrlDecode(secret);
            DateTime issued = DateTime.Now;
            DateTime expire = DateTime.Now.AddHours(10);
            var payload = new Dictionary<string, object>()
            {
                {"iss", "https://localhost/"},
                {"uID", SessionFacade.ID},
                {"email", SessionFacade.USERNAME},
                {"iat", DateTime.Now.ToString()},
                {"exp", DateTime.Now.AddDays(1).ToString()}
            };
            return JWT.Encode(payload, secretKey, JwsAlgorithm.HS256);
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

        User GetUserbyUName(string uname)
        {
            User usr = null;
            using(var db = new AuthDBEntities())
            {
                usr = db.Users.Where(p => p.UserName == uname).SingleOrDefault();
            }
            return usr;
        }
        public static string GetHashString(string inputString)
        {
            if (String.IsNullOrEmpty(inputString))
                return String.Empty;

            using (var sha = new System.Security.Cryptography.SHA256Managed())
            {
                byte[] textData = System.Text.Encoding.UTF8.GetBytes(inputString);
                byte[] hash = sha.ComputeHash(textData);
                return BitConverter.ToString(hash).Replace("-", String.Empty);
            }
        }

    }
}