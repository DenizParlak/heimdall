"""
AWS utility functions for Heimdall
"""

import os
from pathlib import Path
from typing import List, Dict, Optional
import configparser


def get_aws_profiles() -> List[Dict[str, str]]:
    """
    Get list of available AWS profiles from ~/.aws/credentials and ~/.aws/config
    
    Returns:
        List of dicts with profile info: [{'name': 'default', 'region': 'us-east-1'}, ...]
    """
    profiles = {}
    
    # Read credentials file
    credentials_path = Path.home() / '.aws' / 'credentials'
    if credentials_path.exists():
        config = configparser.ConfigParser()
        config.read(credentials_path)
        for section in config.sections():
            profiles[section] = {'name': section, 'region': None}
    
    # Read config file for regions
    config_path = Path.home() / '.aws' / 'config'
    if config_path.exists():
        config = configparser.ConfigParser()
        config.read(config_path)
        for section in config.sections():
            # Config sections are like "profile prod" or "default"
            profile_name = section.replace('profile ', '') if section.startswith('profile ') else section
            
            if profile_name not in profiles:
                profiles[profile_name] = {'name': profile_name, 'region': None}
            
            if config.has_option(section, 'region'):
                profiles[profile_name]['region'] = config.get(section, 'region')
    
    return list(profiles.values())


def get_default_profile() -> Optional[str]:
    """
    Get the default AWS profile to use.
    
    Priority:
    1. 'default' profile if exists
    2. First available profile
    3. None if no profiles found
    
    Returns:
        Profile name or None
    """
    profiles = get_aws_profiles()
    
    if not profiles:
        return None
    
    # Check if 'default' exists
    for profile in profiles:
        if profile['name'] == 'default':
            return 'default'
    
    # Return first available profile
    return profiles[0]['name']


def profile_exists(profile_name: str) -> bool:
    """
    Check if a specific AWS profile exists
    
    Args:
        profile_name: Name of the profile to check
        
    Returns:
        True if profile exists, False otherwise
    """
    profiles = get_aws_profiles()
    return any(p['name'] == profile_name for p in profiles)
