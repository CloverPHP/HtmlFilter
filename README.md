HtmlFilter
===

PHP filtering class to avoid XSS injection.

About:
---

This class implements a HTML filtering system which will avoid JavaScript injection.

The filter() and _filterTag() methods were copied from Zend Framework: 
https://github.com/zendframework/zf1/blob/master/library/Zend/Filter/StripTags.php
and were changed to receive a list of Forbidden tag names and Forbidden attributes.

Additional, the filter() method will remove the attributes if their value contains 'javascript:', 'vbscript:' or 'data:'.

For more details on XSS, please read here:
- http://www.squarefree.com/securitytips/web-developers.html
- https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
- http://htmlpurifier.org/

Examples:
---

```php
// Instantiation
$hf = new htmlFilter();

// Removes 'onclick' attribute
echo $hf->filter('<p style="color:#f00;"><strong onclick="alert(1)">Coool</strong></p>');

// Removes <script> tag
echo $hf->filter('<script src="http://nonexistingsite/script.js"<p>Cool2</p>');

// Removes 'javascript:' from `src` attribute
echo $hf->filter('<img src="javascript:window.alert(1);"/>');

// Removes 'javascript:' from CSS property
echo $hf->filter('<table style="background: url(\'javascript:alert(1)\');"></table>');

// Removes 'javascript:' from URL
echo $hf->filter('<a href="javascript:alert(1);"<p>Hello</p>');
```
