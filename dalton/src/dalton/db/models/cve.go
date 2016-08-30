package models

import "labix.org/v2/mgo/bson"

/*

    These are the models that represent a single CVE (Common Vulnerabilities and Exposure) Models that will be used for parsing,
    storing and manupilating CVEs in the database and the scannerd will use them for Security investigations for detecting Versions and vulnerabilities
    that exist in enumerated and discovered hosts in the network
 */
type CVE struct {
	Id 		   bson.ObjectId     `bson:"_id" json:"db_id"`
	CveId              string            `bson:"cve_id" json:"cve_id"`
	Product            []string          `bson:"products,omitempty" json:"products"`
	DiscoveredDate     string            `bson:"discovered_datetime,omitempty" json:"discovered_datetime"`
	DisclosureDate     string            `bson:"disclosure_datetime,omitempty" json:"disclosure_datetime"`
	ExploitPubDate     string            `bson:"exploit_publish_datetime,omitempty" json:"exploit_publish_datetime"`
	PublishedDate      string            `bson:"published_datetime,omitempty" json:"published_datetime"`
	LastModifiedDate   string            `bson:"last_modified_datetime,omitempty" json:"last_modified_datetime"`
	CVSS               CVSS_Base_Metrics `bson:"cvss,omitempty" json:"cvss"`
	SecurityProtection string            `bson:"security_protection,omitempty" json:"security_protection"`
	CweId              string            `bson:"cwe_id,omitempty" json:"cwe_id"`
	References         []Reference       `bson:"references,omitempty" json:"references"`
	Summary            string            `bson:"summary,omitempty" json:"summary"`
}

type CVSS_Base_Metrics struct {
	Score                float64 `bson:"score,omitempty" json:"score"`
	AccessVector         string  `bson:"access_vector,omitempty" json:"access_vector"`
	AccessComplexity     string  `bson:"access_complexity,omitempty" json:"access_complexity"`
	Authentication       string  `bson:"authentication,omitempty" json:"authentication"`
	ConfidentiallyImpact string  `bson:"confidentiality_impact,omitempty" json:"confidentiality_impact"`
	IntegrityImpact      string  `bson:"integrity_impact,omitempty" json:"integrity_impact"`
	AvailabilityImpact   string  `bson:"availability_impact,omitempty" json:"availability_impact"`
	Source               string  `bson:"source,omitempty" json:"source"`
	GeneratedDate        string  `bson:"generated_on_datetime,omitempty" json:"generated_on_datetime"`
}

type Reference struct {
	ReferenceType string `bson:"reference_type,omitempty" json:"reference_type"`
	Source        string `bson:"reference_source,omitempty" json:"reference_source"`
	URL           string `bson:"reference_url,omitempty" json:"reference_url"`
}
