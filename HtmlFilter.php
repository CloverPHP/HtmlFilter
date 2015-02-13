<?php

/**
 *
 * This class implements a HTML filtering system which will avoid
 * JavaScript injection.
 *
 *
 * These two functions were copied from Zend Framework: 
 * https://github.com/zendframework/zf1/blob/master/library/Zend/Filter/StripTags.php
 * and were changed to receive a list of Forbidden tag names
 * and Forbidden attributes.
 *
 * Also the function Filter() will remove the attributes if their value contains
 * 'javascript:', 'vbscript:' or 'data:'.
 *
 * For more details on XSS, please read here:
 * 1. http://www.squarefree.com/securitytips/web-developers.html
 * 2. https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
 * 3. http://htmlpurifier.org/
 *
 */
 
class HtmlFilter {
  
  private $_tagsForbidden = Array();
  private $_attributesForbidden = Array();
  
  public $tagsForbidden = Array(
                  "script", 
                  "form", 
                  "button", 
                  "input",
                  "style",
                  "meta",
                  "base",
                  "xss",
                  "xml"
                  );
  
  public $attributesForbidden = Array(
                  "seekSegmentTime",
                  "FSCommand"            
                  );
                  

  public function filter($value) {
    $value = (string) $value;
    
    // Load the forbidden tags and attributes
    $this->_tagsForbidden = Array();
    $this->_attributesForbidden = Array();
  
    foreach($this->tagsForbidden as $tag) {
      $this->_tagsForbidden[$tag] = null;
    }
  
    foreach($this->attributesForbidden as $attribute) {
      $this->_attributesForbidden[$attribute] = null;
    }
 
    // Strip HTML comments first
    while (strpos($value, '<!--') !== false) {
      $pos   = strrpos($value, '<!--');
      $start = substr($value, 0, $pos);
      $value = substr($value, $pos);

      // If there is no comment closing tag, strip whole text
      if (!preg_match('/--\s*>/s', $value)) {
        $value = '';
      } else {
        $value = preg_replace('/<(?:!(?:--[\s\S]*?--\s*)?(>))/s', '',  $value);
      }
      
      $value = $start . $value;
    }

    // Initialize accumulator for filtered data
    $dataFiltered = '';
    // Parse the input data iteratively as regular pre-tag text followed by a
    // tag; either may be empty strings
    preg_match_all('/([^<]*)(<?[^>]*>?)/', (string) $value, $matches);

    // Iterate over each set of matches
    foreach ($matches[1] as $index => $preTag) {
      // If the pre-tag text is non-empty, strip any ">" characters from it
      if (strlen($preTag)) {
        $preTag = str_replace('>', '', $preTag);
      }
      // If a tag exists in this match, then filter the tag
      $tag = $matches[2][$index];
      if (strlen($tag)) {
        $tagFiltered = $this->_filterTag($tag);
      } else {
        $tagFiltered = '';
      }
      // Add the filtered pre-tag text and filtered tag to the data buffer
        $dataFiltered .= $preTag . $tagFiltered;
      }

      // Return the filtered data
      return $dataFiltered;
    }

    
  private function _filterTag($tag) {
    // Parse the tag into:
    // 1. a starting delimiter (mandatory)
    // 2. a tag name (if available)
    // 3. a string of attributes (if available)
    // 4. an ending delimiter (if available)
    
    $isMatch = preg_match('~(</?)(\w*)((/(?!>)|[^/>])*)(/?>)~', $tag, $matches);

    // If the tag does not match, then strip the tag entirely
    if (!$isMatch) {
      return '';
    }

    // Save the matches to more meaningfully named variables
    $tagStart      = $matches[1];
    $tagName       = strtolower($matches[2]);
    $tagAttributes = $matches[3];
    $tagEnd        = $matches[5];

    // If the tag is not allowed, then remove the tag entirely
    if (array_key_exists($tagName, $this->_tagsForbidden)) {
      return '';
    }

    // Trim the attribute string of whitespace at the ends
    $tagAttributes = trim($tagAttributes);

    // If there are non-whitespace characters in the attribute string
    if (strlen($tagAttributes)) {
      // Parse iteratively for well-formed attributes
      preg_match_all('/([\w-]+)\s*=\s*(?:(")(.*?)"|(\')(.*?)\')/s', $tagAttributes, $matches);

      // Initialize valid attribute accumulator
      $tagAttributes = '';

      // Iterate over each matched attribute
      foreach ($matches[1] as $index => $attributeName) {
        $attributeName      = strtolower($attributeName);
        $attributeDelimiter = empty($matches[2][$index]) ? $matches[4][$index] : $matches[2][$index];
        $attributeValue     = empty($matches[3][$index]) ? $matches[5][$index] : $matches[3][$index];

        // If the attribute is not allowed, then remove it entirely
        if(substr($attributeName, 0, 2) == "on" || array_key_exists($attributeName, $this->_attributesForbidden) || 
            stristr($attributeValue, "javascript:") || stristr($attributeValue, "vbscript:") || stristr($attributeValue, "data:")) {
          continue;
        }
        // Add the attribute to the accumulator
        $tagAttributes .= " " . $attributeName . "=" . $attributeDelimiter
                           . $attributeValue . $attributeDelimiter;
        }
    }

    // Reconstruct tags ending with "/>" as backwards-compatible XHTML tag
    if (strpos($tagEnd, '/') !== false) {
      $tagEnd = " " . $tagEnd;
    }

    // Return the filtered tag
    return $tagStart . $tagName . $tagAttributes . $tagEnd;
  }
}


