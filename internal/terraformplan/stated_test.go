package terraformplan

import (
	"reflect"
	"testing"
)

// A provider attribute that is Optional and Computed is emitted as unknown when
// the configuration does not set it, and unknown is also what an attribute set
// from something undetermined emits. The two are the same shape in the plan and
// opposite in meaning: the first has a documented default a mapper may apply,
// the second is a value nobody can know yet.
//
// The configuration block separates them, because it records what the author
// wrote. This is the question a mapper has to be able to ask instead of guessing
// -- an unknown GCP firewall direction read as unreadable makes every idiomatic
// firewall undeterminable, and read as INGRESS invents a fact about one that was
// genuinely interpolated.
func TestTheConfigurationSaysWhichAttributesTheAuthorWrote(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "google_compute_firewall.implicit", "mode": "managed",
	      "type": "google_compute_firewall", "name": "implicit",
	      "provider_name": "registry.terraform.io/hashicorp/google",
	      "change": {"actions": ["create"], "before": null,
	                 "after": {"name": "implicit"}, "after_unknown": {"direction": true}}
	    },
	    {
	      "address": "google_compute_firewall.explicit", "mode": "managed",
	      "type": "google_compute_firewall", "name": "explicit",
	      "provider_name": "registry.terraform.io/hashicorp/google",
	      "change": {"actions": ["create"], "before": null,
	                 "after": {"name": "explicit", "direction": "INGRESS"}}
	    }
	  ],
	  "configuration": {
	    "root_module": {
	      "resources": [
	        {
	          "address": "google_compute_firewall.implicit", "mode": "managed",
	          "type": "google_compute_firewall", "name": "implicit",
	          "provider_config_key": "google",
	          "expressions": {
	            "name": {"constant_value": "implicit"},
	            "allow": [{"protocol": {"constant_value": "tcp"}}]
	          }
	        },
	        {
	          "address": "google_compute_firewall.explicit", "mode": "managed",
	          "type": "google_compute_firewall", "name": "explicit",
	          "provider_config_key": "google",
	          "expressions": {
	            "name": {"constant_value": "explicit"},
	            "direction": {"constant_value": "INGRESS"}
	          }
	        }
	      ]
	    }
	  }
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	implicit := changeAt(t, plan, "google_compute_firewall.implicit")
	if !implicit.Configured {
		t.Fatal("a resource the configuration block declares is not reported as configured")
	}
	if implicit.States("direction") {
		t.Error("an attribute the configuration does not mention is reported as written")
	}
	// A nested block is an argument the author wrote, and a mapper asking
	// whether a rule set was stated inline is asking exactly this.
	if !implicit.States("allow") {
		t.Error("a nested block the configuration states is not reported as written")
	}
	if !implicit.States("name") {
		t.Error("a constant argument is not reported as written")
	}
	// Sorted, and carrying the arguments of nested blocks by their path -- the
	// `allow` block's own `protocol` appears as `allow.protocol`, because an
	// attribute inside a block needs the same question asked about it as one at
	// the top.
	if got := implicit.Stated; !reflect.DeepEqual(got, []string{"allow", "allow.protocol", "name"}) {
		t.Errorf("Stated = %v, want the written arguments in sorted order", got)
	}

	explicit := changeAt(t, plan, "google_compute_firewall.explicit")
	if !explicit.States("direction") {
		t.Error("an attribute the configuration sets is not reported as written")
	}
}

// Absence of the configuration block is not absence of the argument. A sanitized
// plan does not say what the author wrote, so nothing may be concluded from the
// silence -- applying a documented default there would be inventing the one fact
// the plan withheld.
func TestWithoutAConfigurationBlockNothingIsKnownAboutWhatWasWritten(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "google_compute_firewall.web", "mode": "managed",
	      "type": "google_compute_firewall", "name": "web",
	      "provider_name": "registry.terraform.io/hashicorp/google",
	      "change": {"actions": ["create"], "before": null, "after": {"name": "web"}}
	    }
	  ]
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	change := changeAt(t, plan, "google_compute_firewall.web")

	if change.Configured {
		t.Fatal("a plan with no configuration block reports its resources as configured")
	}
	if change.States("name") {
		t.Error("an attribute present in after is reported as written, which the plan never said")
	}
	if change.Stated != nil {
		t.Errorf("Stated = %v, want nil: the plan states nothing about what was written", change.Stated)
	}
}

// A resource the plan changes but the configuration does not declare is the same
// silence one resource at a time. It happens: a plan sanitized per resource, or a
// configuration block that lost a module.
func TestAResourceMissingFromTheConfigurationIsNotReportedAsConfigured(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "google_compute_firewall.web", "mode": "managed",
	      "type": "google_compute_firewall", "name": "web",
	      "provider_name": "registry.terraform.io/hashicorp/google",
	      "change": {"actions": ["create"], "before": null, "after": {"name": "web"}}
	    }
	  ],
	  "configuration": {
	    "root_module": {
	      "resources": [
	        {
	          "address": "google_compute_network.vpc", "mode": "managed",
	          "type": "google_compute_network", "name": "vpc",
	          "provider_config_key": "google",
	          "expressions": {"name": {"constant_value": "vpc"}}
	        }
	      ]
	    }
	  }
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	change := changeAt(t, plan, "google_compute_firewall.web")

	if change.Configured || change.States("name") || change.Stated != nil {
		t.Fatalf("configured = %v, stated = %v for a resource the configuration omits",
			change.Configured, change.Stated)
	}
}

// A resource inside a module is reached by its qualified address, the same way
// its references are. An unqualified lookup would hand a module's resource the
// arguments of a root resource with the same local name.
func TestStatedAttributesAreFoundForAModuleResource(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "module.net.google_compute_firewall.web", "module_address": "module.net",
	      "mode": "managed", "type": "google_compute_firewall", "name": "web",
	      "provider_name": "registry.terraform.io/hashicorp/google",
	      "change": {"actions": ["create"], "before": null, "after": {"name": "web"}}
	    },
	    {
	      "address": "google_compute_firewall.web", "mode": "managed",
	      "type": "google_compute_firewall", "name": "web",
	      "provider_name": "registry.terraform.io/hashicorp/google",
	      "change": {"actions": ["create"], "before": null, "after": {"name": "root"}}
	    }
	  ],
	  "configuration": {
	    "root_module": {
	      "resources": [
	        {
	          "address": "google_compute_firewall.web", "mode": "managed",
	          "type": "google_compute_firewall", "name": "web",
	          "provider_config_key": "google",
	          "expressions": {"direction": {"constant_value": "INGRESS"}}
	        }
	      ],
	      "module_calls": {
	        "net": {
	          "source": "./net",
	          "module": {
	            "resources": [
	              {
	                "address": "google_compute_firewall.web", "mode": "managed",
	                "type": "google_compute_firewall", "name": "web",
	                "provider_config_key": "google",
	                "expressions": {"allow": [{"protocol": {"constant_value": "tcp"}}]}
	              }
	            ]
	          }
	        }
	      }
	    }
	  }
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	inner := changeAt(t, plan, "module.net.google_compute_firewall.web")
	if !inner.Configured || inner.States("direction") || !inner.States("allow") {
		t.Errorf("the module resource reports configured = %v, stated = %v; it took the root's arguments",
			inner.Configured, inner.Stated)
	}
	root := changeAt(t, plan, "google_compute_firewall.web")
	if !root.States("direction") || root.States("allow") {
		t.Errorf("the root resource reports stated = %v; it took the module's arguments", root.Stated)
	}
}

// A configuration entry that records no arguments answers nothing about what the
// author wrote, and must not be read as an author who wrote nothing.
//
// Terraform emits such an entry: a resource whose body is only a `dynamic` block
// has no `expressions` key at all, and a sanitizer that strips `expressions` --
// the one place literal values live -- leaves every entry in this shape. This
// repository's own plan fixtures contain it.
//
// Read as an author's silence, it hands every Optional and Computed attribute its
// provider default. An independent review turned that into PASS, exit 0, with no
// findings, on a GCP firewall opening SSH to 0.0.0.0/0: the deny's unknown
// direction was defaulted to INGRESS, it cancelled the grant, and the result was
// a deterministic proof that nothing was open.
func TestAConfigurationThatRecordsNoArgumentsAnswersNothing(t *testing.T) {
	cases := map[string]string{
		"no expressions key": `{
		  "address": "google_compute_firewall.web", "mode": "managed",
		  "type": "google_compute_firewall", "name": "web", "provider_config_key": "google"
		}`,
		"expressions null": `{
		  "address": "google_compute_firewall.web", "mode": "managed",
		  "type": "google_compute_firewall", "name": "web", "provider_config_key": "google",
		  "expressions": null
		}`,
		// A body that is only a dynamic block: Terraform records the
		// provisioner and no expressions at all.
		"only a dynamic block": `{
		  "address": "google_compute_firewall.web", "mode": "managed",
		  "type": "google_compute_firewall", "name": "web", "provider_config_key": "google",
		  "provisioners": [{"type": "local-exec"}]
		}`,
	}

	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			plan, err := Parse([]byte(`{
			  "format_version": "1.2",
			  "resource_changes": [
			    {
			      "address": "google_compute_firewall.web", "mode": "managed",
			      "type": "google_compute_firewall", "name": "web",
			      "provider_name": "registry.terraform.io/hashicorp/google",
			      "change": {"actions": ["create"], "before": null,
			                 "after": {"name": "web"}, "after_unknown": {"direction": true}}
			    }
			  ],
			  "configuration": {"root_module": {"resources": [` + entry + `]}}
			}`))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			change := changeAt(t, plan, "google_compute_firewall.web")

			if change.Configured {
				t.Error("a resource whose arguments were not recorded is reported as configured, " +
					"so every unwritten attribute takes a provider default")
			}
			if change.Stated != nil {
				t.Errorf("Stated = %v, want nil", change.Stated)
			}
			if change.States("direction") {
				t.Error("an argument nobody recorded is reported as written")
			}
		})
	}
}

// An entry that records arguments is still reported as configured, or the fix
// above has turned every plan into one that says nothing.
func TestAConfigurationThatRecordsArgumentsIsStillAnswerable(t *testing.T) {
	plan, err := Parse([]byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "google_compute_firewall.web", "mode": "managed",
	      "type": "google_compute_firewall", "name": "web",
	      "provider_name": "registry.terraform.io/hashicorp/google",
	      "change": {"actions": ["create"], "before": null, "after": {"name": "web"}}
	    }
	  ],
	  "configuration": {"root_module": {"resources": [
	    {
	      "address": "google_compute_firewall.web", "mode": "managed",
	      "type": "google_compute_firewall", "name": "web", "provider_config_key": "google",
	      "expressions": {"name": {"constant_value": "web"}}
	    }
	  ]}}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	change := changeAt(t, plan, "google_compute_firewall.web")

	if !change.Configured || !change.States("name") || change.States("direction") {
		t.Fatalf("configured = %v, stated = %v", change.Configured, change.Stated)
	}
}

// An entry recording an empty argument set is a real answer: the author wrote a
// resource with no arguments, which is different from a plan that did not record
// them. It is reported as configured and states nothing.
func TestAnEmptyArgumentSetIsAnAnswerAndNotASilence(t *testing.T) {
	plan, err := Parse([]byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "google_compute_firewall.web", "mode": "managed",
	      "type": "google_compute_firewall", "name": "web",
	      "provider_name": "registry.terraform.io/hashicorp/google",
	      "change": {"actions": ["create"], "before": null, "after": {"name": "web"}}
	    }
	  ],
	  "configuration": {"root_module": {"resources": [
	    {
	      "address": "google_compute_firewall.web", "mode": "managed",
	      "type": "google_compute_firewall", "name": "web", "provider_config_key": "google",
	      "expressions": {}
	    }
	  ]}}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	change := changeAt(t, plan, "google_compute_firewall.web")

	if !change.Configured {
		t.Error("an explicitly empty argument set is not an unrecorded one")
	}
	if change.States("direction") {
		t.Error("an argument the author did not write is reported as written")
	}
}

// An attribute inside a nested block has the same two meanings for an unknown
// value as a top-level one, and the same need to tell them apart.
//
// Cloud SQL puts the switch that decides whether a database has a public IP at
// settings.ip_configuration.ipv4_enabled, three levels down. An instance writing
// no ip_configuration emits the whole block unknown and Google's default is a
// public IP; an instance writing ipv4_enabled from something unresolvable emits
// the same unknown and no default applies. Recording only top-level arguments
// made those two indistinguishable -- `[database_version name settings]` for
// both -- which is the shape milestone 08's worst defect had.
//
// The walker already builds dotted attribute names for the references it finds,
// so the information was there and only the recording stopped at the top.
func TestTheArgumentsOfANestedBlockAreRecordedByTheirPath(t *testing.T) {
	plan, err := Parse([]byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "google_sql_database_instance.written", "mode": "managed",
	      "type": "google_sql_database_instance", "name": "written",
	      "provider_name": "registry.terraform.io/hashicorp/google",
	      "change": {"actions": ["create"], "before": null, "after": {"name": "written"}}
	    },
	    {
	      "address": "google_sql_database_instance.silent", "mode": "managed",
	      "type": "google_sql_database_instance", "name": "silent",
	      "provider_name": "registry.terraform.io/hashicorp/google",
	      "change": {"actions": ["create"], "before": null, "after": {"name": "silent"}}
	    }
	  ],
	  "configuration": {"root_module": {"resources": [
	    {
	      "address": "google_sql_database_instance.written", "mode": "managed",
	      "type": "google_sql_database_instance", "name": "written",
	      "provider_config_key": "google",
	      "expressions": {
	        "name": {"constant_value": "written"},
	        "settings": [{
	          "tier": {"constant_value": "db-f1-micro"},
	          "ip_configuration": [{
	            "ipv4_enabled": {"constant_value": true},
	            "authorized_networks": [{"value": {"constant_value": "0.0.0.0/0"}}]
	          }]
	        }]
	      }
	    },
	    {
	      "address": "google_sql_database_instance.silent", "mode": "managed",
	      "type": "google_sql_database_instance", "name": "silent",
	      "provider_config_key": "google",
	      "expressions": {
	        "name": {"constant_value": "silent"},
	        "settings": [{"tier": {"constant_value": "db-f1-micro"}}]
	      }
	    }
	  ]}}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	written := changeAt(t, plan, "google_sql_database_instance.written")
	for _, path := range []string{
		// The top-level names, which every existing caller asks for and which
		// must keep working.
		"name", "settings",
		// The nested ones, by the path the configuration nests them at.
		"settings.tier",
		"settings.ip_configuration",
		"settings.ip_configuration.ipv4_enabled",
		"settings.ip_configuration.authorized_networks",
		"settings.ip_configuration.authorized_networks.value",
	} {
		if !written.States(path) {
			t.Errorf("%q is written and is not recorded; stated = %v", path, written.Stated)
		}
	}

	silent := changeAt(t, plan, "google_sql_database_instance.silent")
	if !silent.States("settings.tier") {
		t.Error("a nested argument the author wrote is not recorded")
	}
	for _, path := range []string{
		"settings.ip_configuration",
		"settings.ip_configuration.ipv4_enabled",
	} {
		if silent.States(path) {
			t.Errorf("%q is not written and is recorded; stated = %v", path, silent.Stated)
		}
	}

	// The two resources differ in exactly the fact that decides the verdict,
	// which is what recording only the top level lost.
	if written.States("settings.ip_configuration.ipv4_enabled") ==
		silent.States("settings.ip_configuration.ipv4_enabled") {
		t.Fatal("an instance that writes the switch and one that does not are indistinguishable")
	}
}

// A block index is not part of an argument's identity. The configuration nests
// blocks as arrays, and `settings[0].ip_configuration[0].ipv4_enabled` is the
// same argument as the one in any other instance of the block -- a caller asking
// about it should not have to know how many there were.
func TestABlockIndexIsNotPartOfAnArgumentsPath(t *testing.T) {
	plan, err := Parse([]byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_security_group.web", "mode": "managed",
	      "type": "aws_security_group", "name": "web",
	      "provider_name": "registry.terraform.io/hashicorp/aws",
	      "change": {"actions": ["create"], "before": null, "after": {"name": "web"}}
	    }
	  ],
	  "configuration": {"root_module": {"resources": [
	    {
	      "address": "aws_security_group.web", "mode": "managed",
	      "type": "aws_security_group", "name": "web", "provider_config_key": "aws",
	      "expressions": {
	        "ingress": [
	          {"from_port": {"constant_value": 22}, "cidr_blocks": {"constant_value": ["0.0.0.0/0"]}},
	          {"from_port": {"constant_value": 443}}
	        ]
	      }
	    }
	  ]}}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	change := changeAt(t, plan, "aws_security_group.web")

	if !change.States("ingress") || !change.States("ingress.from_port") {
		t.Errorf("stated = %v", change.Stated)
	}
	if !change.States("ingress.cidr_blocks") {
		t.Error("an argument written in only one instance of a repeated block is not recorded")
	}
	for _, indexed := range []string{"ingress[0]", "ingress[0].from_port", "ingress[1].from_port"} {
		if change.States(indexed) {
			t.Errorf("%q is recorded, so a caller has to know how many blocks there were", indexed)
		}
	}
}
