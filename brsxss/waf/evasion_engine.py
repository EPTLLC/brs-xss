#!/usr/bin/env python3

"""
BRS-XSS Evasion Engine

Main WAF evasion engine with adaptive strategies and machine learning approach.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import random
from typing import Dict, List, Optional, Any

from .evasion_types import EvasionTechnique, EvasionResult
from .encoding_engine import EncodingEngine
from .obfuscation_engine import ObfuscationEngine
from .waf_specific_evasion import WAFSpecificEvasion
from .detector import WAFInfo, WAFType
from ..utils.logger import Logger

logger = Logger("waf.evasion_engine")


class EvasionEngine:
    """
    Main WAF evasion system for BRS-XSS.
    
    Functions:
    - Adaptive strategies for specific WAFs
    - ML approach to technique selection
    - Multiple technique combination
    - Mutation fuzzing for new bypasses
    - Stealth assessment of techniques
    """
    
    def __init__(self):
        """Initialize evasion engine"""
        self.encoding_engine = EncodingEngine()
        self.obfuscation_engine = ObfuscationEngine()
        self.waf_specific = WAFSpecificEvasion()
        
        # Successful techniques (learning)
        self.successful_techniques: Dict[WAFType, List[EvasionTechnique]] = {}
        
    def generate_evasions(
        self,
        payload: str,
        detected_wafs: List[WAFInfo],
        max_variations: int = 50
    ) -> List[EvasionResult]:
        """
        Main method for generating evasion payloads.
        
        Args:
            payload: Original payload
            detected_wafs: Detected WAFs
            max_variations: Maximum number of variations
            
        Returns:
            List of evasion payloads
        """
        logger.info(f"Generating {max_variations} evasion techniques for payload: {payload[:50]}...")
        
        evasions = []
        
        if not detected_wafs:
            # If no WAF detected, use generic techniques
            evasions.extend(self._generate_generic_evasions(payload))
        else:
            # WAF-specific techniques
            for waf in detected_wafs:
                waf_evasions = self._generate_waf_specific_evasions(payload, waf)
                evasions.extend(waf_evasions)
        
        # Add techniques
        evasions.extend(self._generate_advanced_evasions(payload))
        
        # Combined techniques
        evasions.extend(self._generate_combined_evasions(payload, detected_wafs))
        
        # Limit quantity and sort by effectiveness
        evasions = sorted(evasions, key=lambda x: x.success_probability, reverse=True)
        
        final_evasions = evasions[:max_variations]
        
        logger.success(f"Generated {len(final_evasions)} evasion techniques")
        
        return final_evasions
    
    def _generate_generic_evasions(self, payload: str) -> List[EvasionResult]:
        """Generate generic evasion techniques"""
        evasions = []
        
        # URL encoding
        evasions.append(EvasionResult(
            original_payload=payload,
            evaded_payload=self.encoding_engine.url_encode(payload),
            technique=EvasionTechnique.URL_ENCODING,
            success_probability=0.7,
            stealth_level=0.8,
            complexity=2,
            target_wafs=[],
            transformation_steps=["url_encode"],
            encoding_used="url"
        ))
        
        # Double URL encoding
        evasions.append(EvasionResult(
            original_payload=payload,
            evaded_payload=self.encoding_engine.url_encode(payload, double=True),
            technique=EvasionTechnique.DOUBLE_URL_ENCODING,
            success_probability=0.6,
            stealth_level=0.7,
            complexity=3,
            target_wafs=[],
            transformation_steps=["double_url_encode"],
            encoding_used="double_url"
        ))
        
        # HTML encoding
        evasions.append(EvasionResult(
            original_payload=payload,
            evaded_payload=self.encoding_engine.html_encode(payload),
            technique=EvasionTechnique.HTML_ENCODING,
            success_probability=0.65,
            stealth_level=0.6,
            complexity=2,
            target_wafs=[],
            transformation_steps=["html_encode"],
            encoding_used="html_entities"
        ))
        
        # Case variation
        case_varied = ''.join([c.upper() if i % 2 == 0 else c.lower() 
                              for i, c in enumerate(payload)])
        evasions.append(EvasionResult(
            original_payload=payload,
            evaded_payload=case_varied,
            technique=EvasionTechnique.CASE_VARIATION,
            success_probability=0.5,
            stealth_level=0.9,
            complexity=1,
            target_wafs=[],
            transformation_steps=["case_variation"]
        ))
        
        # Whitespace injection
        whitespace_injected = payload.replace(' ', '\t').replace('<', '< ').replace('>', ' >')
        evasions.append(EvasionResult(
            original_payload=payload,
            evaded_payload=whitespace_injected,
            technique=EvasionTechnique.WHITESPACE_INJECTION,
            success_probability=0.6,
            stealth_level=0.8,
            complexity=2,
            target_wafs=[],
            transformation_steps=["whitespace_inject"]
        ))
        
        return evasions
    
    def _generate_waf_specific_evasions(self, payload: str, waf: WAFInfo) -> List[EvasionResult]:
        """Generate WAF-specific techniques"""
        evasions = []
        
        # Get WAF-specific bypasses
        if waf.waf_type == WAFType.CLOUDFLARE:
            cf_evasions = self.waf_specific.cloudflare_evasion(payload)
            for evaded in cf_evasions:
                evasions.append(EvasionResult(
                    original_payload=payload,
                    evaded_payload=evaded,
                    technique=EvasionTechnique.WAF_SPECIFIC,
                    success_probability=0.8,
                    stealth_level=0.7,
                    complexity=4,
                    target_wafs=[WAFType.CLOUDFLARE],
                    transformation_steps=["cloudflare_specific"]
                ))
        
        elif waf.waf_type == WAFType.AWS_WAF:
            aws_evasions = self.waf_specific.aws_waf_evasion(payload)
            for evaded in aws_evasions:
                evasions.append(EvasionResult(
                    original_payload=payload,
                    evaded_payload=evaded,
                    technique=EvasionTechnique.WAF_SPECIFIC,
                    success_probability=0.75,
                    stealth_level=0.6,
                    complexity=4,
                    target_wafs=[WAFType.AWS_WAF],
                    transformation_steps=["aws_waf_specific"]
                ))
        
        elif waf.waf_type == WAFType.INCAPSULA:
            inc_evasions = self.waf_specific.incapsula_evasion(payload)
            for evaded in inc_evasions:
                evasions.append(EvasionResult(
                    original_payload=payload,
                    evaded_payload=evaded,
                    technique=EvasionTechnique.WAF_SPECIFIC,
                    success_probability=0.7,
                    stealth_level=0.8,
                    complexity=5,
                    target_wafs=[WAFType.INCAPSULA],
                    transformation_steps=["incapsula_specific"]
                ))
        
        elif waf.waf_type == WAFType.MODSECURITY:
            mod_evasions = self.waf_specific.modsecurity_evasion(payload)
            for evaded in mod_evasions:
                evasions.append(EvasionResult(
                    original_payload=payload,
                    evaded_payload=evaded,
                    technique=EvasionTechnique.WAF_SPECIFIC,
                    success_probability=0.65,
                    stealth_level=0.7,
                    complexity=3,
                    target_wafs=[WAFType.MODSECURITY],
                    transformation_steps=["modsecurity_specific"]
                ))
        
        return evasions
    
    def _generate_advanced_evasions(self, payload: str) -> List[EvasionResult]:
        """Generate evasion techniques"""
        evasions = []
        
        # JavaScript obfuscation (if JS payload)
        if any(js_indicator in payload.lower() for js_indicator in ['alert', 'confirm', 'prompt', 'eval']):
            
            # String concatenation
            concat_payload = self.obfuscation_engine.string_concatenation(payload)
            evasions.append(EvasionResult(
                original_payload=payload,
                evaded_payload=concat_payload,
                technique=EvasionTechnique.STRING_CONCAT,
                success_probability=0.7,
                stealth_level=0.5,
                complexity=6,
                target_wafs=[],
                transformation_steps=["js_string_concat"],
                obfuscation_level=6
            ))
            
            # Unicode obfuscation
            unicode_payload = self.obfuscation_engine.unicode_obfuscation(payload)
            evasions.append(EvasionResult(
                original_payload=payload,
                evaded_payload=unicode_payload,
                technique=EvasionTechnique.UNICODE_ESCAPE,
                success_probability=0.75,
                stealth_level=0.4,
                complexity=7,
                target_wafs=[],
                transformation_steps=["js_unicode_obfuscation"],
                obfuscation_level=7
            ))
            
            # Array obfuscation
            array_payload = self.obfuscation_engine.array_obfuscation(payload)
            evasions.append(EvasionResult(
                original_payload=payload,
                evaded_payload=array_payload,
                technique=EvasionTechnique.JS_OBFUSCATION,
                success_probability=0.8,
                stealth_level=0.3,
                complexity=8,
                target_wafs=[],
                transformation_steps=["js_array_obfuscation"],
                obfuscation_level=8
            ))
        
        # Comment insertion
        comment_injected = payload.replace('<', '<!--x--><').replace('>', '><!--x-->')
        evasions.append(EvasionResult(
            original_payload=payload,
            evaded_payload=comment_injected,
            technique=EvasionTechnique.COMMENT_INSERTION,
            success_probability=0.6,
            stealth_level=0.7,
            complexity=4,
            target_wafs=[],
            transformation_steps=["comment_injection"]
        ))
        
        # Mixed encoding
        mixed_encoded = self.encoding_engine.mixed_encoding(payload)
        evasions.append(EvasionResult(
            original_payload=payload,
            evaded_payload=mixed_encoded,
            technique=EvasionTechnique.UNICODE_ENCODING,
            success_probability=0.7,
            stealth_level=0.4,
            complexity=6,
            target_wafs=[],
            transformation_steps=["mixed_encoding"],
            encoding_used="mixed"
        ))
        
        return evasions
    
    def _generate_combined_evasions(self, payload: str, detected_wafs: List[WAFInfo]) -> List[EvasionResult]:
        """Generate combined techniques"""
        evasions = []
        
        # Combination of URL encoding + case variation
        step1 = self.encoding_engine.url_encode(payload)
        step2 = ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(step1)])
        
        evasions.append(EvasionResult(
            original_payload=payload,
            evaded_payload=step2,
            technique=EvasionTechnique.URL_ENCODING,  # Main technique
            success_probability=0.65,
            stealth_level=0.6,
            complexity=5,
            target_wafs=[waf.waf_type for waf in detected_wafs],
            transformation_steps=["url_encode", "case_variation"],
            encoding_used="url+case"
        ))
        
        # Combination of HTML encoding + whitespace injection
        step1 = self.encoding_engine.html_encode(payload)
        step2 = step1.replace(';', '; ').replace('&', ' &')
        
        evasions.append(EvasionResult(
            original_payload=payload,
            evaded_payload=step2,
            technique=EvasionTechnique.HTML_ENCODING,
            success_probability=0.6,
            stealth_level=0.5,
            complexity=6,
            target_wafs=[waf.waf_type for waf in detected_wafs],
            transformation_steps=["html_encode", "whitespace_inject"],
            encoding_used="html+whitespace"
        ))
        
        return evasions
    
    def mutate_payload(self, payload: str, mutations: int = 10) -> List[EvasionResult]:
        """
        Mutation fuzzing - generate payload mutations.
        
        Args:
            payload: Original payload
            mutations: Number of mutations
            
        Returns:
            List of mutated payloads
        """
        mutations_list = []
        
        for i in range(mutations):
            mutated = payload
            
            # Random mutations
            mutation_type = random.choice([
                'char_insert', 'char_delete', 'char_replace', 
                'case_flip', 'encoding_mix'
            ])
            
            if mutation_type == 'char_insert':
                pos = random.randint(0, len(mutated))
                char = random.choice('/<>"\' \t\n')
                mutated = mutated[:pos] + char + mutated[pos:]
            
            elif mutation_type == 'char_delete':
                if len(mutated) > 1:
                    pos = random.randint(0, len(mutated) - 1)
                    mutated = mutated[:pos] + mutated[pos+1:]
            
            elif mutation_type == 'char_replace':
                if len(mutated) > 0:
                    pos = random.randint(0, len(mutated) - 1)
                    new_char = random.choice('/<>"\' \t\n')
                    mutated = mutated[:pos] + new_char + mutated[pos+1:]
            
            elif mutation_type == 'case_flip':
                pos = random.randint(0, len(mutated) - 1)
                char = mutated[pos]
                if char.isalpha():
                    new_char = char.swapcase()
                    mutated = mutated[:pos] + new_char + mutated[pos+1:]
            
            elif mutation_type == 'encoding_mix':
                # Encode random characters
                result = ""
                for char in mutated:
                    if random.random() < 0.3:  # 30% encoding probability
                        encoding_type = random.choice(['url', 'html', 'unicode'])
                        if encoding_type == 'url':
                            result += f'%{ord(char):02x}'
                        elif encoding_type == 'html':
                            result += f'&#{ord(char)};'
                        elif encoding_type == 'unicode':
                            result += f'\\u{ord(char):04x}'
                    else:
                        result += char
                mutated = result
            
            # Mutation assessment
            success_prob = max(0.1, 0.8 - (i * 0.05))  # Decreases with each mutation
            
            mutations_list.append(EvasionResult(
                original_payload=payload,
                evaded_payload=mutated,
                technique=EvasionTechnique.MUTATION_FUZZING,
                success_probability=success_prob,
                stealth_level=0.5,
                complexity=3 + i // 3,
                target_wafs=[],
                transformation_steps=[f"mutation_{mutation_type}"],
                obfuscation_level=3
            ))
        
        return mutations_list
    
    def learn_from_success(self, waf_type: WAFType, technique: EvasionTechnique):
        """Learn from successful techniques"""
        if waf_type not in self.successful_techniques:
            self.successful_techniques[waf_type] = []
        
        if technique not in self.successful_techniques[waf_type]:
            self.successful_techniques[waf_type].append(technique)
            logger.info(f"Learned successful technique {technique.value} for {waf_type.value}")
    
    def get_best_techniques_for_waf(self, waf_type: WAFType) -> List[EvasionTechnique]:
        """Get best techniques for specific WAF"""
        return self.successful_techniques.get(waf_type, [])
    
    def get_evasion_stats(self) -> Dict[str, Any]:
        """Evasion technique statistics"""
        return {
            'total_learned_wafs': len(self.successful_techniques),
            'techniques_by_waf': {
                waf.value: [tech.value for tech in techniques]
                for waf, techniques in self.successful_techniques.items()
            },
            'most_successful_technique': self._get_most_successful_technique()
        }
    
    def _get_most_successful_technique(self) -> Optional[str]:
        """Get most successful technique"""
        technique_counts: Dict[EvasionTechnique, int] = {}
        
        for techniques in self.successful_techniques.values():
            for technique in techniques:
                technique_counts[technique] = technique_counts.get(technique, 0) + 1
        
        if technique_counts:
            best_technique = max(technique_counts.items(), key=lambda x: x[1])[0] if technique_counts else None  # technique_counts.get)
            return best_technique.value if best_technique else "unknown"
        
        return None