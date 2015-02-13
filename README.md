HtmlFilter
===

A very useful HTML filter class written in PHP to avoid XSS injection.

Examples:
---

```php
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
