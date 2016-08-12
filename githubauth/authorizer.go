package githubauth

import (
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

type GithubAuthorizer struct {
	client     *github.Client
	accessTeam int
	adminTeam  int
}

func NewGithubAuthorizer(token, organization, accessGroup, adminGroup string) (*GithubAuthorizer, error) {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)

	githubClient := github.NewClient(oauth2.NewClient(oauth2.NoContext, ts))

	var accessTeamID, adminTeamID int
	if organization != "" {
		teams, _, err := githubClient.Organizations.ListTeams(organization, &github.ListOptions{})
		if err != nil {
			return nil, errors.Wrap(err, "list teams github api error")
		}

		for _, t := range teams {
			if t.Name != nil && t.ID != nil {
				if *t.Name == accessGroup {
					accessTeamID = *t.ID
				}
				if *t.Name == adminGroup {
					adminTeamID = *t.ID
				}
			}
		}
	}

	return &GithubAuthorizer{
		client:     githubClient,
		accessTeam: accessTeamID,
		adminTeam:  adminTeamID,
	}, nil
}

func (ga GithubAuthorizer) Authorize(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	authorizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	var foundKey bool

	keys, _, err := ga.client.Users.ListKeys(conn.User(), &github.ListOptions{})
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

	if ga.accessTeam != 0 {
		// Ensure user is in group
		isMember, _, err := ga.client.Organizations.IsTeamMember(ga.accessTeam, conn.User())
		if err != nil {
			return nil, errors.Wrapf(err, "is team member (%d) github api error", ga.accessTeam)
		}
		if !isMember {
			return nil, errors.New("no access to group")
		}
	}

	permissions := &ssh.Permissions{}

	if ga.adminTeam != 0 {
		isMember, _, err := ga.client.Organizations.IsTeamMember(ga.adminTeam, conn.User())
		if err != nil {
			return nil, errors.Wrapf(err, "is team member (%d) github api error", ga.adminTeam)
		}
		if isMember {
			permissions.Extensions = map[string]string{
				"admin-access": "true",
			}
		}
	}

	logrus.Infof("Logging from %s using %s", conn.User(), authorizedKey)
	return permissions, nil
}
