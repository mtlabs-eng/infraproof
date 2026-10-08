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

// An argument whose value is composed partly from outside the configuration's
// resources is a different thing from one that names none of them, and the
// difference decides whether a list can be read as complete.
//
// References deliberately drop what is not a resource -- `var`, `local`,
// `count.index`, a module output -- because correlation is about resources and a
// variable correlates nothing. That is right, and it silently destroyed the one
// signal a mapper needed: `vpc_security_group_ids = concat([aws_security_group.a.id],
// var.extra)` left exactly one placeable reference, so an allow list the plan
// describes half of read as the whole one. The verdict was PASS.
//
// So the fact is recorded rather than the filter relaxed: Opaque names the
// arguments that drew on something the configuration does not declare.
func TestAnArgumentDrawingOnSomethingOutsideTheConfigurationIsRecorded(t *testing.T) {
	plan, err := Parse([]byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_db_instance.partial", "mode": "managed",
	      "type": "aws_db_instance", "name": "partial", "provider_name": "p",
	      "change": {"actions": ["create"], "before": null, "after": {"identifier": "partial"}}
	    },
	    {
	      "address": "aws_db_instance.whole", "mode": "managed",
	      "type": "aws_db_instance", "name": "whole", "provider_name": "p",
	      "change": {"actions": ["create"], "before": null, "after": {"identifier": "whole"}}
	    },
	    {
	      "address": "aws_security_group.a", "mode": "managed",
	      "type": "aws_security_group", "name": "a", "provider_name": "p",
	      "change": {"actions": ["create"], "before": null, "after": {"name": "a"}}
	    }
	  ],
	  "configuration": {"root_module": {"resources": [
	    {
	      "address": "aws_db_instance.partial", "mode": "managed",
	      "type": "aws_db_instance", "name": "partial", "provider_config_key": "aws",
	      "expressions": {
	        "identifier": {"constant_value": "partial"},
	        "vpc_security_group_ids": {"references": [
	          "aws_security_group.a.id", "aws_security_group.a", "var.extra"]}
	      }
	    },
	    {
	      "address": "aws_db_instance.whole", "mode": "managed",
	      "type": "aws_db_instance", "name": "whole", "provider_config_key": "aws",
	      "expressions": {
	        "identifier": {"constant_value": "whole"},
	        "vpc_security_group_ids": {"references": [
	          "aws_security_group.a.id", "aws_security_group.a"]}
	      }
	    },
	    {
	      "address": "aws_security_group.a", "mode": "managed",
	      "type": "aws_security_group", "name": "a", "provider_config_key": "aws",
	      "expressions": {"name": {"constant_value": "a"}}
	    }
	  ]}}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	partial := changeAt(t, plan, "aws_db_instance.partial")
	if !partial.DrawsOnOpaque("vpc_security_group_ids") {
		t.Errorf("the attribute drew on var.extra and is not recorded; opaque = %v", partial.Opaque)
	}
	// The resource references it does have are still there: the filter is not
	// relaxed, only the loss is recorded.
	var named int
	for _, reference := range partial.References {
		if reference.Attribute == "vpc_security_group_ids" {
			named++
		}
	}
	if named != 1 {
		t.Errorf("%d resource references survived, want 1", named)
	}

	whole := changeAt(t, plan, "aws_db_instance.whole")
	if whole.DrawsOnOpaque("vpc_security_group_ids") {
		t.Errorf("an attribute naming only resources is recorded as drawing on something else; "+
			"opaque = %v", whole.Opaque)
	}
	if whole.DrawsOnOpaque("identifier") {
		t.Error("a constant argument is recorded as drawing on something else")
	}

	// And the two differ in exactly the fact that decides whether the list can
	// be read as complete.
	if partial.DrawsOnOpaque("vpc_security_group_ids") ==
		whole.DrawsOnOpaque("vpc_security_group_ids") {
		t.Fatal("a half-described list and a fully described one are indistinguishable")
	}
}

// A plan with no configuration records nothing about what an argument drew on,
// for the same reason it records nothing about what was written: the question is
// not answerable, and answering it no would say the list is complete.
func TestWithoutAConfigurationNothingDrawsOnAnythingKnown(t *testing.T) {
	plan, err := Parse([]byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_db_instance.main", "mode": "managed",
	      "type": "aws_db_instance", "name": "main", "provider_name": "p",
	      "change": {"actions": ["create"], "before": null, "after": {"identifier": "main"}}
	    }
	  ]
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	change := changeAt(t, plan, "aws_db_instance.main")

	if change.Opaque != nil || change.DrawsOnOpaque("vpc_security_group_ids") {
		t.Errorf("opaque = %v for a plan that records no configuration", change.Opaque)
	}
	if change.Configured {
		t.Error("the resource is reported as configured")
	}
}

// TestASingleNestedBlockIsABlockAndNotAnExpression corrects this package's model
// of the configuration grammar, which said a nested block is always an array.
//
// A block with `nesting_mode: single` -- `timeouts`, and the same shape on 641
// aws resource types -- is written as a bare **object**, not as an array of one.
// Measured on a real plan: `"timeouts": {"create": {"constant_value": "40m"}}`.
//
// Both hand-written readers of that grammar got it wrong, in opposite
// directions. `collectArguments` recorded `timeouts` and stopped, so
// `timeouts.create` was absent from Stated although the author wrote it, and a
// caller asking `Unwritten("timeouts.create")` was told nobody wrote it -- which
// is how a provider default gets applied over something somebody wrote. And the
// expression walker handed the block to the attribute reader, which looks for a
// `references` key that is not there, so every reference inside a single-nested
// block was dropped in silence: no correlation, no Opaque record, no parse error.
//
// How live each half is, measured against `terraform providers schema -json` for
// hashicorp/aws v6, hashicorp/google v6 and hashicorp/azurerm v5:
//
//   - 641 single-nested blocks on aws, 723 on google, 1106 on azurerm.
//   - Of those, the number with a settable attribute and a name other than
//     `timeouts`: **zero**, on all three.
//
// So the Stated half is live -- `timeouts.create` is a real argument a real plan
// records and this build reported as unwritten -- and the reference half is
// defensive: no single-nested block in any of the three providers can hold a
// reference today, because `timeouts` holds duration strings. A hand-authored
// fixture carrying one would be exactly the fiction that caused three of
// milestone 08's defects, so the decision itself is tested instead, in
// TestIsExpressionTellsAnAttributeFromASingleNestedBlock.
//
// Nothing in the three families reads a single-nested block at all: `settings`,
// `ip_configuration`, `authorized_networks`, `ingress` and `security_rule` are
// list- or set-nested, measured. The grammar was stated as exhaustive in a doc
// comment, which is what made it worth measuring.
//
// The two forms are told apart by their keys: an attribute expression carries
// only `constant_value` and `references`, and anything else is a block. That is
// Terraform's encoding and it is ambiguous at the edge -- a provider attribute
// literally named `references` would be read as an expression -- which the
// grammar's own comment now says rather than claiming certainty.
func TestASingleNestedBlockIsABlockAndNotAnExpression(t *testing.T) {
	const address = "aws_db_instance.withsingle"

	var change ResourceChange
	for _, candidate := range parseFixture(t, "single-nested-block").ResourceChanges {
		if candidate.Address == address {
			change = candidate
		}
	}
	if change.Address == "" {
		t.Fatalf("the fixture holds no change at %s", address)
	}

	stated := change.States("timeouts")
	if !stated {
		t.Fatal("the author wrote a timeouts block and the configuration does not " +
			"record it at all, so the fixture has stopped carrying its shape")
	}
	if !change.States("timeouts.create") {
		t.Fatal("the author wrote timeouts.create and this build reports it as " +
			"unwritten, which is how a provider default is applied over something " +
			"somebody wrote")
	}
	if change.States("timeouts.delete") {
		t.Fatal("nobody wrote timeouts.delete and this build reports it as written")
	}

	// And the reference beside it still arrives, which is what proves the block
	// is not being read as an expression at the cost of the attributes around it.
	var named bool
	for _, reference := range change.References {
		if reference.Attribute == "vpc_security_group_ids" &&
			reference.Target == "aws_security_group.ref" {
			named = true
		}
	}
	if !named {
		t.Fatal("the security group this database names is no longer in its references")
	}
}
