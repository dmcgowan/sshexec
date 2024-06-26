package githubauth

import (
	"context"
	"strings"

	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

type GithubAuthorizer struct {
	ctx          context.Context
	client       *github.Client
	organization string
	teams        map[string]int64
}

func NewGithubAuthorizer(ctx context.Context, token, organization string, teams ...string) (*GithubAuthorizer, error) {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)

	githubClient := github.NewClient(oauth2.NewClient(ctx, ts))

	teamIDs := map[string]int64{}
	if organization != "" {
		listOptions := &github.ListOptions{
			Page:    1,
			PerPage: 100,
		}
		for {
			ghteams, _, err := githubClient.Teams.ListTeams(ctx, organization, listOptions)

			if err != nil {
				return nil, errors.Wrap(err, "list teams github api error")
			}

			for _, t := range ghteams {
				if t.Name != nil && t.ID != nil {
					for _, team := range teams {
						if *t.Name == team {
							teamIDs[team] = *t.ID
							break
						}
					}
				}
			}

			if len(ghteams) != listOptions.PerPage || len(teams) == len(teamIDs) {
				break
			}

			listOptions.Page = listOptions.Page + 1
		}
	}

	if len(teams) != len(teamIDs) {
		return nil, errors.Errorf("could not access all requested github teams")
	}

	return &GithubAuthorizer{
		ctx:          ctx,
		client:       githubClient,
		organization: organization,
		teams:        teamIDs,
	}, nil
}

func (ga GithubAuthorizer) Authorize(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	authorizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	var foundKey bool

	keys, _, err := ga.client.Users.ListKeys(ga.ctx, conn.User(), &github.ListOptions{})
	if err != nil {
		logrus.Infof("Error getting key: %v", err)
		return nil, errors.Wrap(err, "list keys github api error")
	}
	// TODO: cache response

	for _, k := range keys {
		if k.Key != nil && *k.Key == authorizedKey {
			foundKey = true
			break
		}
	}

	if !foundKey {
		return nil, errors.New("no authorized key")
	}

	permissions := &ssh.Permissions{
		Extensions: map[string]string{},
	}

	if ga.organization != "" {
		permissions.Extensions["organization"] = ga.organization

		var hasPermission bool
		for team, teamID := range ga.teams {
			_, resp, err := ga.client.Teams.GetTeamMembership(ga.ctx, teamID, conn.User())
			if err != nil {
				return nil, errors.Wrapf(err, "is team member (%d) github api error", team)
			}
			if resp.StatusCode == 200 {
				permissions.Extensions["team-"+team] = "true"
				hasPermission = true
			}
		}

		if !hasPermission {
			return nil, errors.New("no valid team membership")
		}
	}

	logrus.Infof("Logging from %s using %s", conn.User(), authorizedKey)
	return permissions, nil
}

func IsTeamMember(permissions *ssh.Permissions, organization, team string) bool {
	if permissions.Extensions == nil {
		return false
	}

	if permissions.Extensions["organization"] != organization {
		return false
	}

	if permissions.Extensions["team-"+team] != "true" {
		return false
	}

	return true
}
