<?php
/**
 * LDAP_User_Mappings - Enables the mapping of WP usermeta to LDAP attributes
 * @package Simple LDAP Plugin, Version: 1.4.0.5.1
 * @author Dan Crimmins [dcrimmi@searshc.com]
 * 
 */

class LDAP_User_Mappings {
	
	//Form field prefix for ldap alt DN
	const ALT_DN_PREFIX = 'ldap_alt_dn_';
	
	//Form field prefix for ldap attr name 
	const LDAP_ATTR_PREFIX = 'ldap_attr_';
	
	/** 
	 * The WP option key for ldap user attr map
	 * @var string
	 * @access private
	 */
	private $_wp_mapping_option = 'simpleldap_user_attr_map';
	
	/**
	 * Array of WP user metakeys to exclude
	 * @var array
	 * @access private
	 */
	private $_wp_user_meta_exclusions =   array('admin_color',
												'comment_shortcuts',
												'dismissed_wp_pointers',
												'rich_editing',
												'show_admin_bar_front',
												'show_welcome_panel',
												'use_ssl',
												'wp_capabilities',
												'wp_dashboard_quick_press_last_post_id',
												'wp_user-settings',
												'wp_user-settings-time',
												'wp_user_level',
												'first_name',
												'last_name',
												'description',
												'nickname');
	/**
	 * Array of user ldap mappings
	 * 
	 * @var array
	 * @access public
	 * @
	 */
	public $ldap_mappings;
	
	/**
	 * Array of WP usermeta keys (with excluded meta keys removed)
	 * 
	 * @var array 
	 * @access public
	 */
	public $wp_user_meta;
	
	/**
	 * Array of WP user meta data
	 * 
	 * @var array
	 * @access public
	 */
	public $wp_userdata;
	
	/**
	 * Array of LDAP entry values
	 * 
	 * @var array
	 * @access private
	 */
	private $_ldap_attribute_values;
	
	
	
	/**
	 * Constructor
	 * 
	 * @param void
	 * @return void
	 */
	
	function __construct() {
		
		//Set $wp_user_meta, stripping out excluded keys
		$this->get_wp_usermeta();
		
		//Set $ldap_mappings
		$this->get_ldap_mappings();
		
	}
	
	/**
	 * Retrieve LDAP mapping option (simpleldap_user_attr_map), and set $ldap_mappings property.
	 * If option doesn't exist, create it with empty values.
	 * 
	 * @method get_ldap_mappings()
	 * @access private
	 * @param void
	 * @return void
	 */
	
	private function get_ldap_mappings() {
		
		if(! $this->ldap_mappings = get_option($this->_wp_mapping_option, false)) {
			
			//ldap mapping option doesn't exist yet -- Create ldap mappings for each meta key with empty values
			foreach($this->wp_user_meta as $key=>$obj) {
				
				$this->ldap_mappings[$obj->meta_key] = array('alt_dn' => '',
															 'ldap_attr' => '');
			}
			
		} else {
			
			//Option exists, strip out exclusions
			foreach($this->ldap_mappings as $metakey=>$attr) {
				
				if(in_array($metakey, $this->_wp_user_meta_exclusions)) {
					
					unset($this->ldap_mappings[$metakey]);
				}
			}
			
		}
	}
	
	/**
	 * Accepts post data and parses out ldap user mappings to set ldap_mappings.
	 * 
	 * @param array $post - Post data
	 * @return object - instance of object of this class
	 */
	
	public function set_ldap_mappings($post) {
		
		if(is_array($post)) {
			
			foreach($this->wp_user_meta as $key=>$obj) {
				
				$alt_dn = isset($post[self::ALT_DN_PREFIX . $obj->meta_key]) ? trim(strtolower($post[self::ALT_DN_PREFIX . $obj->meta_key])) : '';
				$ldap_attr = isset($post[self::LDAP_ATTR_PREFIX . $obj->meta_key]) ? trim(strtolower($post[self::LDAP_ATTR_PREFIX . $obj->meta_key])) : '';
				
				$this->ldap_mappings[$obj->meta_key] = array('alt_dn' => $alt_dn,
															 'ldap_attr' => $ldap_attr);
			} 
		}
		
		return $this;
	}
	
	/**
	 * Save value of $ldap_mappings to ldap mapping option
	 * in wp_options table
	 * 
	 * @param void
	 * @return void
	 * @uses update_option()
	 */
	public function save() {
		
		if(is_array($this->ldap_mappings)) {
			
			update_option($this->_wp_mapping_option, $this->ldap_mappings);
		}
	}
	
	/**
	 * Iterates over $ldap_mappings and runs ldap queries, retrieves values and sets
	 * WP user data ($wp_userdata) 
	 * 
	 * @param resource $ldap_conn
	 * @param string $base_dn
	 * @param array $base_ldap_results
	 * @access public
	 */
	
	public function get_ldap_attributes($ldap_conn, $base_dn, $base_ldap_results) {
		
		if($ldap_conn) {
			
			$this->_ldap_attribute_values = $base_ldap_results;
			
			foreach($this->ldap_mappings as $metakey=>$attrs) {
				
				//if there is a value for this attr proceed
				if(strlen(trim($attrs['ldap_attr']))) {
					
					//is there an alternate DN?
					if(strlen(trim($attrs['alt_dn']))) {
						
						$dn_filter = explode(';', $attrs['alt_dn']);
						
						if(count($dn_filter) == 2) { //If there are more or less than 2 elements, there's an issue
							
							$dn = trim($dn_filter[0]);
							$filter = trim($dn_filter[1]);
							
						} else {
							
							die('You must include a filter with alternate DN.');
						}
						
					} else {
						
						$dn = $base_dn;
						$filter = false;
					}
					
						//Retrieve LDAP result
						if($filter) { //Use Alt DN and filter
							
							//Make sure that we have a value for the filter
							if($filter_value = $this->get_ldap_attr_value($filter)) {
								
								//search ldap
								$search_filter = $filter . '=' . $filter_value;
								
								$rs = ldap_search($ldap_conn, $dn, $search_filter);
								$value = ldap_get_entries($ldap_conn, $rs);
							
								//Add result to $wp_userdata
								$this->add_userdata($metakey, $value[0][$attrs['ldap_attr']][0]);
									
							} else {
								
								die('The filter attribute was not found');
							}
							
						} else { //Use Base DN
							
							//Grab value for base DN search results
							if($filter_value = $this->get_ldap_attr_value($attrs['ldap_attr'])) {
								
								//Add result to $wp_userdata
								$this->add_userdata($metakey, $filter_value);
							}
							
						}
				}
				
			}
		} 
		
	}
	
	/**
	 * Adds elements to $wp_userdata property
	 * 
	 * @param string $metakey
	 * @param string $value
	 * @access private
	 */
	private function add_userdata($metakey, $value) {
		
		$this->wp_userdata[$metakey] = $value;
	}
	
	/**
	 * Retrieves the value of ldap attribute from search results ($_ldap_attribute_values)
	 * 
	 * @param string $attr_name
	 * @return bool|string - Returns either false if element not found or value of ldap attribute
	 * @see $_ldap_attribute_values
	 * @access private
	 */
	private function get_ldap_attr_value($attr_name) {
		
		if(isset($this->_ldap_attribute_values[0][$attr_name][0])) {
				
			return $this->_ldap_attribute_values[0][$attr_name][0];
				
		} else {
			
			return false;
		}
	}
	
	/**
	 * Retrieves all user meta keys, sets $wp_user_meta property
	 * and strips out excluded meta keys ($_wp_user_meta_exclusions)
	 * 
	 * @param void
	 * @return void
	 * 
	 * @uses $wpdb
	 * @see $wp_user_meta_property
	 * @see $_wp_user_meta_exclusions
	 */
	
	private function get_wp_usermeta() {
		
		global $wpdb;
		
		$sql = "SELECT DISTINCT meta_key FROM $wpdb->usermeta";
		$this->wp_user_meta = $wpdb->get_results($sql);
		
		//Strip excluded user meta
		array_walk($this->wp_user_meta, array($this, 'strip_exclusions'), &$this->wp_user_meta);
	}
	
	/**
	 * Callback function that removes excluded user meta values ($_wp_user_meta_exclusions). 
	 * 
	 * @param object $value
	 * @param int $key
	 * @param array $arr
	 * @see $_wp_user_meta_exclusions
	 * @return void
	 */
	private function strip_exclusions(&$value, $key, $arr) {
		
		if(in_array($value->meta_key, $this->_wp_user_meta_exclusions)) {
			
			unset($arr[$key]);
		}
	}
}