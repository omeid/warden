
use warden::*;
use uuid::Uuid;

pub struct MemProvider<C, CS>
    where C: Context,
          CS: Conditions<C>
{
    policies: Vec<Policy<C, CS>>,
}

impl<C, CS> PolicyProvider<C, CS> for MemProvider<C, CS>
    where C: Context,
          CS: Conditions<C>
{
    fn add_policy(&self, policy: Policy<C, CS>) -> Result {
        policy.id = Uuid::new_v4();
        self.policies.push(policy);

        Ok(policy.id)

    }
    fn subject_policies<'a>(&'a self,
                            subject: &String,
                            action: &String)
                            -> &'a Iterator<Item = &Policy<C, CS>> {
        &self.policies.iter().filter(|&pol| -> bool {
            pol.subjects.contains(subject ) &&
            pol.actions.contains(action)
        })
    }
}
