using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace AuthenticationServer.Models.AuthenticationModels
{
    public class TwoStepLogin
    {
        [Required]
        [Display(Name = "Email")]
        [EmailAddress]
        public string Email { get; set; }

        [Display(Name = "Verification Code")]
        public string VerificationCode{get; set;}
    }
}