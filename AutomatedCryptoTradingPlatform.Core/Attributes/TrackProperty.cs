using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AutomatedCryptoTradingPlatform.Core.Attributes
{
    /// <summary>
    /// Attribute dùng để track property của một class và lấy metadata của nó
    /// </summary>
    [AttributeUsage(AttributeTargets.Property)]
    public class TrackProperty : Attribute
    {

    }
}
