using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace AuthenticationServer.Models.AuthenticationModels
{
    public class AddPhoneModel
    {
        [Required]
        [Display(Name = "Phone Number")]
        [Phone]
        public string Ph_No { get; set; }

        [Required]
        [Phone]
        [Display(Name = "Confirm Phone Number")]
        public string Confirm_Ph_No { get; set; }
    }
}